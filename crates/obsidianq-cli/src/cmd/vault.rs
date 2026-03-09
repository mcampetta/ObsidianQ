//! `obsidianq vault` subcommand family — create / add / extract / ls / mount / unmount.
//!
//! Password/key handling mirrors the existing `mount.rs` pattern.

use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use clap::{Args, Subcommand};
use zeroize::{Zeroize, Zeroizing};

use obsidianq_core::{
    crypto::{
        kdf::{self, Argon2Params, MasterKey},
        kem::{self, CT_BYTES, DK_BYTES, EK_BYTES},
    },
    format::Mode,
};
use obsidianq_vault::{
    container::CreateParams,
    format::{immutable_kem_capacity_for_version, ImmutableHeader, BLOCK_SIZE_DEFAULT, VERSION},
    VaultContainer, VaultError,
};

use super::{read_priv, read_pub};

const MULTI_MAGIC_V1: &[u8; 4] = b"MRK1";
const MULTI_MAGIC_V2: &[u8; 4] = b"MRK2";
const WRAP_NONCE_LEN: usize = 24;
const WRAP_CT_LEN: usize = 48; // 32-byte key + 16-byte tag
const WRAP_INFO: &[u8] = b"obsidianq-v1-mrk2-wrap";

// ---------------------------------------------------------------------------
// CLI argument types
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub cmd: VaultCmd,
}

#[derive(Subcommand)]
pub enum VaultCmd {
    /// Create a new .vault vault
    Create(CreateArgs),
    /// Add a file or directory tree to a vault
    Add(AddArgs),
    /// Extract files from a vault
    Extract(ExtractArgs),
    /// List vault contents
    Ls(LsArgs),
    /// Remove a file from a vault
    Remove(RemoveArgs),
    /// Re-encrypt a vault to a new key set (password or recipient public keys)
    Rekey(RekeyArgs),
    /// Mount vault as a read/write virtual drive (requires WinFSP)
    Mount(VaultMountArgs),
    /// Unmount a mounted vault drive
    Unmount(VaultUnmountArgs),
}

// ---------------------------------------------------------------------------
// vault create
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct CreateArgs {
    /// Output .vault file (if extension is omitted, .vault is appended)
    #[arg(long)]
    pub out: PathBuf,

    /// Pre-allocate space (e.g. 512M, 2G). 0 = auto-grow.
    #[arg(long, default_value = "0")]
    pub max_size: String,

    /// Block size in bytes (default 65536)
    #[arg(long, default_value_t = BLOCK_SIZE_DEFAULT)]
    pub block_size: u32,

    /// Read password from stdin (one line, no confirm)
    #[arg(long, conflicts_with_all = &["pubkey"])]
    pub password_stdin: bool,

    /// Prompt for password interactively
    #[arg(long, conflicts_with_all = &["pubkey", "password_stdin"])]
    pub password: bool,

    /// Public key file for PQC-mode vaults
    #[arg(long = "pubkey", conflicts_with_all = &["password", "password_stdin"])]
    pub pubkey: Vec<PathBuf>,

    /// Cipher suite
    #[arg(long, default_value = "xchacha20",
          value_parser = ["xchacha20", "aesgcm"])]
    pub suite: String,
}

pub fn run_create(args: CreateArgs) -> Result<()> {
    use rand::RngCore;

    let suite = parse_suite(&args.suite)?;

    let initial_blocks = parse_size_arg(&args.max_size)
        .map(|bytes| bytes / args.block_size as u64)
        .unwrap_or(0);

    let mut file_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut file_id);

    if args.pubkey.is_empty() && !args.password && !args.password_stdin {
        bail!("specify one of --password, --password-stdin, or --pubkey <key>");
    }

    let (master_key, kem_data, mode) = if !args.pubkey.is_empty() {
        derive_key_pqc(&args.pubkey)?
    } else {
        let password = read_password(args.password_stdin, true)?;
        derive_key_password(&password)?
    };

    let params = CreateParams {
        master_key,
        kem_data,
        mode,
        suite,
        file_id,
        block_size: args.block_size,
        initial_blocks,
    };

    let out_path = normalize_vault_path_create(args.out);
    let vc = VaultContainer::create(&out_path, params)
        .with_context(|| format!("create vault {}", out_path.display()))?;
    drop(vc);

    println!("Created vault: {}", out_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// vault add
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct AddArgs {
    /// Target .vault vault (.obsqv is accepted for compatibility)
    #[arg(long)]
    pub vault: PathBuf,

    /// Local file or directory to import
    #[arg(long)]
    pub src: PathBuf,

    /// Destination path inside vault (default: /<src_basename>)
    #[arg(long)]
    pub dest: Option<String>,

    #[arg(long, conflicts_with = "privkey")]
    pub password_stdin: bool,

    #[arg(long, conflicts_with = "password_stdin")]
    pub privkey: Option<PathBuf>,
}

pub fn run_add(args: AddArgs) -> Result<()> {
    let vault_path = normalize_vault_path_use(args.vault);
    let master_key = open_vault_key(&vault_path, args.password_stdin, args.privkey.as_deref())?;
    let mut vc = VaultContainer::open(&vault_path, master_key).context("open vault")?;

    let basename = args
        .src
        .file_name()
        .and_then(|n| n.to_str())
        .context("invalid source path")?;
    let vault_path = args.dest.clone().unwrap_or_else(|| format!("/{basename}"));

    if args.src.is_dir() {
        vc.import_tree(&args.src, &vault_path)
            .context("import tree")?;
        println!(
            "Added directory tree '{}' → '{vault_path}'",
            args.src.display()
        );
    } else {
        let bytes = vc
            .import_file(&args.src, &vault_path)
            .context("import file")?;
        println!(
            "Added '{}' → '{vault_path}' ({bytes} bytes)",
            args.src.display()
        );
    }

    vc.flush().context("flush vault")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// vault extract
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct ExtractArgs {
    /// Source .vault vault (.obsqv is accepted for compatibility)
    #[arg(long)]
    pub vault: PathBuf,

    /// Local directory to extract into
    #[arg(long)]
    pub dest: PathBuf,

    /// Vault path to extract (default: all)
    #[arg(long, default_value = "/")]
    pub path: String,

    #[arg(long, conflicts_with = "privkey")]
    pub password_stdin: bool,

    #[arg(long, conflicts_with = "password_stdin")]
    pub privkey: Option<PathBuf>,
}

pub fn run_extract(args: ExtractArgs) -> Result<()> {
    let vault_path = normalize_vault_path_use(args.vault);
    let master_key = open_vault_key(&vault_path, args.password_stdin, args.privkey.as_deref())?;
    let mut vc = VaultContainer::open(&vault_path, master_key).context("open vault")?;

    let info = vc
        .stat(&args.path)
        .with_context(|| format!("stat {}", args.path))?;
    if info.is_dir {
        vc.export_tree(&args.path, &args.dest)
            .context("export tree")?;
    } else {
        std::fs::create_dir_all(&args.dest).context("create destination directory")?;
        let name = args
            .path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .context("invalid file path")?;
        let out = args.dest.join(name);
        vc.export_file(&args.path, &out)
            .with_context(|| format!("export file {}", args.path))?;
    }
    println!("Extracted '{}' → '{}'", args.path, args.dest.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// vault ls
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct LsArgs {
    /// .vault vault file (.obsqv is accepted for compatibility)
    #[arg(long)]
    pub vault: PathBuf,

    /// Vault path to list (default: /)
    #[arg(long, default_value = "/")]
    pub path: String,

    /// List recursively
    #[arg(long, short = 'r')]
    pub recursive: bool,

    #[arg(long, conflicts_with = "privkey")]
    pub password_stdin: bool,

    #[arg(long, conflicts_with = "password_stdin")]
    pub privkey: Option<PathBuf>,
}

pub fn run_ls(args: LsArgs) -> Result<()> {
    let vault_path = normalize_vault_path_use(args.vault);
    let master_key = open_vault_key(&vault_path, args.password_stdin, args.privkey.as_deref())?;
    let mut vc = VaultContainer::open(&vault_path, master_key).context("open vault")?;

    list_recursive(&mut vc, &args.path, args.recursive, 0)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// vault remove
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct RemoveArgs {
    /// .vault vault file (.obsqv is accepted for compatibility)
    #[arg(long)]
    pub vault: PathBuf,

    /// File path inside vault to remove (e.g. /docs/readme.txt)
    #[arg(long)]
    pub path: String,

    /// Recursively remove directories and their contents.
    #[arg(long)]
    pub recursive: bool,

    #[arg(long, conflicts_with = "privkey")]
    pub password_stdin: bool,

    #[arg(long, conflicts_with = "password_stdin")]
    pub privkey: Option<PathBuf>,
}

pub fn run_remove(args: RemoveArgs) -> Result<()> {
    let vault_path = normalize_vault_path_use(args.vault);
    let master_key = open_vault_key(&vault_path, args.password_stdin, args.privkey.as_deref())?;
    let mut vc = VaultContainer::open(&vault_path, master_key).context("open vault")?;
    match vc.delete_file(&args.path) {
        Ok(()) => {}
        Err(VaultError::IsADirectory(_)) => {
            if args.recursive {
                remove_tree_recursive(&mut vc, &args.path)
                    .with_context(|| format!("remove directory tree {}", args.path))?;
            } else {
                vc.remove_dir(&args.path)
                    .with_context(|| format!("remove directory {}", args.path))?;
            }
        }
        Err(e) => return Err(anyhow::anyhow!(e)).with_context(|| format!("remove {}", args.path)),
    }
    vc.flush().context("flush vault")?;
    println!("Removed '{}'", args.path);
    Ok(())
}

fn remove_tree_recursive(vc: &mut VaultContainer, path: &str) -> Result<()> {
    let p = path.trim_end_matches('/');
    if p.is_empty() || p == "/" {
        bail!("refusing to recursively remove root '/'");
    }

    let entries = vc
        .list_dir(p)
        .with_context(|| format!("list directory {}", p))?;

    for entry in entries {
        let child = if p == "/" {
            format!("/{}", entry.name)
        } else {
            format!("{}/{}", p, entry.name)
        };
        if entry.is_dir {
            remove_tree_recursive(vc, &child)?;
        } else {
            vc.delete_file(&child)
                .with_context(|| format!("delete file {}", child))?;
        }
    }

    vc.remove_dir(p)
        .with_context(|| format!("remove directory {}", p))
}

fn list_recursive(
    vc: &mut VaultContainer,
    path: &str,
    recursive: bool,
    depth: usize,
) -> Result<()> {
    let entries = vc.list_dir(path).with_context(|| format!("list {path}"))?;
    for info in &entries {
        let type_ch = if info.is_dir { 'd' } else { '-' };
        let indent = "  ".repeat(depth);
        let size_str = if info.is_dir {
            String::from("         -")
        } else {
            format!("{:>10}", info.size)
        };
        println!("{indent}{type_ch}  {size_str}  {}", info.name);

        if recursive && info.is_dir {
            let child = if path == "/" {
                format!("/{}", info.name)
            } else {
                format!("{path}/{}", info.name)
            };
            list_recursive(vc, &child, recursive, depth + 1)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// vault rekey
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct RekeyArgs {
    /// Source .vault vault (.obsqv is accepted for compatibility)
    #[arg(long)]
    pub vault: PathBuf,

    /// Destination .vault file (if extension is omitted, .vault is appended)
    #[arg(long)]
    pub out: PathBuf,

    /// Current password from stdin (source vault unlock)
    #[arg(long, conflicts_with = "privkey")]
    pub password_stdin: bool,

    /// Current private key (source vault unlock)
    #[arg(long, conflicts_with = "password_stdin")]
    pub privkey: Option<PathBuf>,

    /// New password from stdin (destination vault lock)
    #[arg(long, conflicts_with_all = &["new_password", "new_pubkey"])]
    pub new_password_stdin: bool,

    /// Prompt for new password (destination vault lock)
    #[arg(long, conflicts_with_all = &["new_password_stdin", "new_pubkey"])]
    pub new_password: bool,

    /// New recipient public keys (repeat for multi-recipient destination vault)
    #[arg(long = "new-pubkey", conflicts_with_all = &["new_password", "new_password_stdin"])]
    pub new_pubkey: Vec<PathBuf>,
}

pub fn run_rekey(args: RekeyArgs) -> Result<()> {
    use rand::RngCore;

    if !args.new_password && !args.new_password_stdin && args.new_pubkey.is_empty() {
        bail!("specify one of --new-password, --new-password-stdin, or --new-pubkey <key>");
    }

    let src_path = normalize_vault_path_use(args.vault);
    let dst_path = normalize_vault_path_create(args.out);

    if src_path == dst_path {
        bail!("--out must be a different path than --vault");
    }
    if dst_path.exists() {
        bail!("destination already exists: {}", dst_path.display());
    }

    let mut src_hdr_f = std::fs::File::open(&src_path).context("open source vault header")?;
    let src_header =
        ImmutableHeader::read_from(&mut src_hdr_f).context("read source vault header")?;
    let src_len = std::fs::metadata(&src_path)
        .context("stat source vault")?
        .len();
    let initial_blocks = src_len / src_header.block_size as u64;

    let old_master = open_vault_key(&src_path, args.password_stdin, args.privkey.as_deref())?;
    let mut src = VaultContainer::open(&src_path, old_master).context("open source vault")?;

    let (new_master, kem_data, mode) = if !args.new_pubkey.is_empty() {
        derive_key_pqc(&args.new_pubkey)?
    } else {
        let new_pw = read_password(args.new_password_stdin, true)?;
        derive_key_password(&new_pw)?
    };

    let mut file_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut file_id);
    let params = CreateParams {
        master_key: new_master,
        kem_data,
        mode,
        suite: src_header.suite,
        file_id,
        block_size: src_header.block_size,
        initial_blocks,
    };
    let mut dst = VaultContainer::create(&dst_path, params).context("create destination vault")?;

    copy_vault_tree(&mut src, &mut dst, "/")?;
    dst.flush().context("flush destination vault")?;

    println!("Rekeyed vault:");
    println!("  Source: {}", src_path.display());
    println!("  Dest  : {}", dst_path.display());
    Ok(())
}

fn copy_vault_tree(src: &mut VaultContainer, dst: &mut VaultContainer, path: &str) -> Result<()> {
    let entries = src
        .list_dir(path)
        .with_context(|| format!("list source directory {}", path))?;

    for info in entries {
        let child = if path == "/" {
            format!("/{}", info.name)
        } else {
            format!("{}/{}", path, info.name)
        };

        if info.is_dir {
            dst.create_dir(&child)
                .with_context(|| format!("create destination directory {}", child))?;
            dst.set_attr(&child, info.attr)
                .with_context(|| format!("set attributes on {}", child))?;
            dst.set_times(&child, info.created, info.modified, info.accessed)
                .with_context(|| format!("set timestamps on {}", child))?;
            copy_vault_tree(src, dst, &child)?;
            continue;
        }

        copy_vault_file(src, dst, &child, &info)?;
    }

    Ok(())
}

fn copy_vault_file(
    src: &mut VaultContainer,
    dst: &mut VaultContainer,
    path: &str,
    info: &obsidianq_vault::EntryInfo,
) -> Result<()> {
    dst.create_file(path)
        .with_context(|| format!("create destination file {}", path))?;

    let src_h = src
        .open_handle(path)
        .with_context(|| format!("open source file {}", path))?;
    let mut dst_h = dst
        .open_handle(path)
        .with_context(|| format!("open destination file {}", path))?;

    let mut offset = 0u64;
    let mut buf = vec![0u8; (src.block_usable_bytes() as usize).max(64 * 1024)];
    while offset < src_h.size {
        let to_read = ((src_h.size - offset) as usize).min(buf.len());
        let n = src
            .read_range(&src_h.block_map, src_h.size, offset, &mut buf[..to_read])
            .with_context(|| format!("read source file {}", path))?;
        if n == 0 {
            break;
        }
        dst.write_range(
            path,
            &mut dst_h.block_map,
            &mut dst_h.size,
            offset,
            &buf[..n],
        )
        .with_context(|| format!("write destination file {}", path))?;
        offset += n as u64;
    }

    dst.set_attr(path, info.attr)
        .with_context(|| format!("set attributes on {}", path))?;
    dst.set_times(path, info.created, info.modified, info.accessed)
        .with_context(|| format!("set timestamps on {}", path))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// vault mount
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct VaultMountArgs {
    /// .vault vault file (not required when --mock is set; .obsqv is accepted)
    #[arg(long, required_unless_present = "mock")]
    pub vault: Option<PathBuf>,

    /// Drive letter (e.g. Z or Z:)
    #[arg(long)]
    pub drive: String,

    #[arg(long, conflicts_with = "privkey")]
    pub password_stdin: bool,

    #[arg(long, conflicts_with = "password_stdin")]
    pub privkey: Option<PathBuf>,

    /// Mount a diagnostic mock filesystem instead of a real vault.
    /// The mock contains a single /hello.txt file and logs all WinFSP callbacks.
    /// Use this to verify that the WinFSP callback wiring works independently.
    #[arg(long)]
    pub mock: bool,

    /// Write a per-callback trace log to this file (created/appended, flushed per line).
    /// Reliable even when stderr is buffered by pipe redirection.
    /// Example: --vfs-log C:\Temp\obsq_vfs.log
    #[arg(long, value_name = "PATH")]
    pub vfs_log: Option<PathBuf>,

    /// FSP_FSCTL_VOLUME_PARAMS.Version value to pass to WinFSP volume params.
    /// Useful for WinFSP compatibility diagnostics.
    #[arg(long, value_name = "U16", default_value_t = 1)]
    pub volparams_version: u16,
}

pub fn run_vault_mount(args: VaultMountArgs) -> Result<()> {
    let dl = args
        .drive
        .trim_end_matches(':')
        .chars()
        .next()
        .context("--drive must be a letter such as Z or Z:")?
        .to_ascii_uppercase();
    if !('A'..='Z').contains(&dl) {
        bail!("invalid drive letter '{dl}'");
    }

    if !obsidianq_fs::is_winfsp_available() {
        bail!(
            "WinFSP is not installed.\n\
             Download: https://github.com/winfsp/winfsp/releases"
        );
    }

    let log_path = args.vfs_log.as_deref();
    let volparams_version = args.volparams_version;

    if args.mock {
        println!("Mounting mock filesystem at {dl}: (diagnostic mode)");
        return obsidianq_fs::mount_vault_mock(dl, log_path, volparams_version)
            .map_err(|e| anyhow::anyhow!("{e}"));
    }

    let vault = args.vault.context("--vault is required (or use --mock)")?;
    let vault = normalize_vault_path_use(vault);
    let master_key = open_vault_key(&vault, args.password_stdin, args.privkey.as_deref())?;

    println!("Opening vault: {}", vault.display());
    println!("Mount at: {dl}:");

    obsidianq_fs::mount_vault(&vault, master_key, dl, log_path, volparams_version)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

// ---------------------------------------------------------------------------
// vault unmount
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct VaultUnmountArgs {
    /// Drive letter to unmount
    #[arg(long)]
    pub drive: String,
}

pub fn run_vault_unmount(args: VaultUnmountArgs) -> Result<()> {
    let dl = args
        .drive
        .trim_end_matches(':')
        .chars()
        .next()
        .context("--drive must be a letter")?
        .to_ascii_uppercase();

    obsidianq_fs::unmount_vault(dl).map_err(|e| anyhow::anyhow!("{e}"))
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub fn run(args: VaultArgs) -> Result<()> {
    match args.cmd {
        VaultCmd::Create(a) => run_create(a),
        VaultCmd::Add(a) => run_add(a),
        VaultCmd::Extract(a) => run_extract(a),
        VaultCmd::Ls(a) => run_ls(a),
        VaultCmd::Remove(a) => run_remove(a),
        VaultCmd::Rekey(a) => run_rekey(a),
        VaultCmd::Mount(a) => run_vault_mount(a),
        VaultCmd::Unmount(a) => run_vault_unmount(a),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn parse_suite(s: &str) -> Result<obsidianq_core::format::SuiteId> {
    use obsidianq_core::format::SuiteId;
    match s {
        "xchacha20" => Ok(SuiteId::XChaCha20Poly1305),
        "aesgcm" => Ok(SuiteId::Aes256Gcm),
        other => bail!("unknown suite '{other}'"),
    }
}

fn parse_size_arg(s: &str) -> Option<u64> {
    if s == "0" {
        return None;
    }
    if let Some(n) = s.strip_suffix('G').or_else(|| s.strip_suffix('g')) {
        return n.parse::<u64>().ok().map(|v| v * 1024 * 1024 * 1024);
    }
    if let Some(n) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        return n.parse::<u64>().ok().map(|v| v * 1024 * 1024);
    }
    s.parse::<u64>().ok()
}

fn read_password(from_stdin: bool, confirm: bool) -> Result<Zeroizing<String>> {
    if from_stdin {
        let mut raw = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut raw)
            .context("read password")?;
        let pw = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned());
        raw.zeroize();
        Ok(pw)
    } else {
        let pw = rpassword::prompt_password("Password: ").context("password prompt")?;
        if confirm {
            let pw2 = rpassword::prompt_password("Confirm  : ").context("confirm prompt")?;
            if pw != pw2 {
                bail!("passwords do not match");
            }
        }
        Ok(Zeroizing::new(pw))
    }
}

fn derive_key_password(password: &str) -> Result<(MasterKey, Vec<u8>, Mode)> {
    use rand::RngCore;
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = kdf::derive_password_key(password.as_bytes(), &salt, &Argon2Params::default())
        .context("key derivation")?;
    Ok((key, salt.to_vec(), Mode::Password))
}

fn derive_key_pqc(pk_paths: &[PathBuf]) -> Result<(MasterKey, Vec<u8>, Mode)> {
    use rand::RngCore;
    if pk_paths.len() == 1 {
        let ek_raw = read_pub(&pk_paths[0]).context("read public key")?;
        if ek_raw.len() != EK_BYTES {
            bail!(
                "public key is {} bytes, expected {}",
                ek_raw.len(),
                EK_BYTES
            );
        }
        let ek_arr: [u8; EK_BYTES] = ek_raw.try_into().unwrap();
        let (ct, ss) = kem::encapsulate(&ek_arr).context("KEM encapsulate")?;

        let mut hkdf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hkdf_salt);
        let key = kdf::derive_root_key(ss.as_bytes(), &hkdf_salt).context("root key")?;

        let mut kem_data = Vec::with_capacity(CT_BYTES + 32);
        kem_data.extend_from_slice(&ct);
        kem_data.extend_from_slice(&hkdf_salt);
        return Ok((key, kem_data, Mode::Pqc));
    }

    let count = pk_paths.len();

    let mut hkdf_salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut hkdf_salt);
    let mut master_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master_bytes);
    let key = MasterKey::from_bytes(master_bytes);

    let total_len = 4 + 2 + count * (CT_BYTES + WRAP_NONCE_LEN + WRAP_CT_LEN) + 32;
    if total_len > u16::MAX as usize {
        bail!(
            "too many recipients for vault header format ({} bytes > 65535)",
            total_len
        );
    }
    let kem_capacity = immutable_kem_capacity_for_version(VERSION)?;
    if total_len > kem_capacity {
        bail!(
            "too many recipients for vault header capacity ({} bytes > {})",
            total_len,
            kem_capacity
        );
    }

    let mut kem_data = Vec::with_capacity(total_len);
    kem_data.extend_from_slice(MULTI_MAGIC_V2);
    kem_data.extend_from_slice(&(count as u16).to_le_bytes());

    for (idx, path) in pk_paths.iter().enumerate() {
        let ek_raw =
            read_pub(path).with_context(|| format!("read public key {}", path.display()))?;
        if ek_raw.len() != EK_BYTES {
            bail!(
                "public key {} is {} bytes, expected {}",
                path.display(),
                ek_raw.len(),
                EK_BYTES
            );
        }
        let ek_arr: [u8; EK_BYTES] = ek_raw.try_into().unwrap();
        let (ct, ss) = kem::encapsulate(&ek_arr).context("KEM encapsulate")?;
        let wrap_key = kdf::derive_root_key(ss.as_bytes(), &hkdf_salt).context("root key")?;
        let cipher = XChaCha20Poly1305::new(wrap_key.as_bytes().into());
        let mut wrap_nonce = [0u8; WRAP_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut wrap_nonce);
        let mut aad = Vec::with_capacity(WRAP_INFO.len() + 2 + 4 + 4 + CT_BYTES);
        aad.extend_from_slice(WRAP_INFO);
        aad.extend_from_slice(&1u16.to_le_bytes());
        aad.extend_from_slice(MULTI_MAGIC_V2);
        aad.extend_from_slice(&(idx as u32).to_le_bytes());
        aad.extend_from_slice(&ct);
        let wrapped = cipher
            .encrypt(
                wrap_nonce.as_slice().into(),
                Payload {
                    msg: key.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("recipient key-wrap encrypt failed"))?;
        if wrapped.len() != WRAP_CT_LEN {
            bail!("unexpected wrapped master-key length {}", wrapped.len());
        }
        kem_data.extend_from_slice(&ct);
        kem_data.extend_from_slice(&wrap_nonce);
        kem_data.extend_from_slice(&wrapped);
    }
    kem_data.extend_from_slice(&hkdf_salt);
    Ok((key, kem_data, Mode::Pqc))
}

/// Derive master key by reading the vault header and decrypting with password/privkey.
fn open_vault_key(
    vault_path: &Path,
    password_stdin: bool,
    privkey: Option<&Path>,
) -> Result<MasterKey> {
    let mut f = std::fs::File::open(vault_path).context("open vault")?;
    let header = ImmutableHeader::read_from(&mut f).context("read vault header")?;

    match header.mode {
        Mode::Password => {
            if !password_stdin && privkey.is_none() {
                bail!("password-mode vault: use --password-stdin");
            }
            let pw = if password_stdin {
                read_password(true, false)?
            } else {
                Zeroizing::new(rpassword::prompt_password("Password: ").context("prompt")?)
            };
            if header.kem_data.len() != 32 {
                bail!("malformed vault header: expected 32-byte salt");
            }
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&header.kem_data);
            kdf::derive_password_key(pw.as_bytes(), &salt, &Argon2Params::default())
                .context("key derivation")
        }
        Mode::Pqc => {
            let pk_path = privkey.context("PQC-mode vault: use --privkey <key>")?;
            let dk_raw = read_priv(pk_path).context("read private key")?;
            if dk_raw.len() != DK_BYTES {
                bail!(
                    "private key is {} bytes, expected {}",
                    dk_raw.len(),
                    DK_BYTES
                );
            }
            let dk_arr: [u8; DK_BYTES] = dk_raw.try_into().unwrap();
            if header.kem_data.starts_with(MULTI_MAGIC_V2) {
                if header.kem_data.len() < 4 + 2 + 32 {
                    bail!("malformed vault header: multi-recipient KEM data too short");
                }
                let count = u16::from_le_bytes([header.kem_data[4], header.kem_data[5]]) as usize;
                let expected = 4 + 2 + count * (CT_BYTES + WRAP_NONCE_LEN + WRAP_CT_LEN) + 32;
                if header.kem_data.len() != expected {
                    bail!("malformed vault header: expected {} KEM bytes", expected);
                }
                let salt_off = expected - 32;
                let mut hkdf_salt = [0u8; 32];
                hkdf_salt.copy_from_slice(&header.kem_data[salt_off..]);
                let canonical = header.canonical_bytes();
                let mut off = 6usize;
                for idx in 0..count {
                    let ct_arr: [u8; CT_BYTES] = header.kem_data[off..off + CT_BYTES]
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("KEM ciphertext slice has wrong length"))?;
                    off += CT_BYTES;
                    let wrap_nonce = &header.kem_data[off..off + WRAP_NONCE_LEN];
                    off += WRAP_NONCE_LEN;
                    let wrapped = &header.kem_data[off..off + WRAP_CT_LEN];
                    off += WRAP_CT_LEN;
                    let ss = match kem::decapsulate(&dk_arr, &ct_arr) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let wrap_key =
                        kdf::derive_root_key(ss.as_bytes(), &hkdf_salt).context("root key")?;
                    let cipher = XChaCha20Poly1305::new(wrap_key.as_bytes().into());
                    let mut aad = Vec::with_capacity(WRAP_INFO.len() + 2 + 4 + 4 + CT_BYTES);
                    aad.extend_from_slice(WRAP_INFO);
                    aad.extend_from_slice(&1u16.to_le_bytes());
                    aad.extend_from_slice(MULTI_MAGIC_V2);
                    aad.extend_from_slice(&(idx as u32).to_le_bytes());
                    aad.extend_from_slice(&ct_arr);
                    let plain = match cipher.decrypt(
                        wrap_nonce.into(),
                        Payload {
                            msg: wrapped,
                            aad: &aad,
                        },
                    ) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if plain.len() != 32 {
                        continue;
                    }
                    let mut candidate = [0u8; 32];
                    candidate.copy_from_slice(&plain);
                    let mk = MasterKey::from_bytes(candidate);
                    if vault_header_mac_matches(&canonical, header.immutable_mac, &mk) {
                        return Ok(mk);
                    }
                }
                bail!("no recipient entry matched provided private key");
            } else if header.kem_data.starts_with(MULTI_MAGIC_V1) {
                if header.kem_data.len() < 4 + 2 + 32 {
                    bail!("malformed vault header: multi-recipient KEM data too short");
                }
                let count = u16::from_le_bytes([header.kem_data[4], header.kem_data[5]]) as usize;
                let expected = 4 + 2 + count * (CT_BYTES + 32) + 32;
                if header.kem_data.len() != expected {
                    bail!("malformed vault header: expected {} KEM bytes", expected);
                }
                let salt_off = expected - 32;
                let mut hkdf_salt = [0u8; 32];
                hkdf_salt.copy_from_slice(&header.kem_data[salt_off..]);
                let canonical = header.canonical_bytes();
                let mut off = 6usize;
                for _ in 0..count {
                    let ct_arr: [u8; CT_BYTES] =
                        header.kem_data[off..off + CT_BYTES].try_into().unwrap();
                    off += CT_BYTES;
                    let wrapped = &header.kem_data[off..off + 32];
                    off += 32;
                    let ss = match kem::decapsulate(&dk_arr, &ct_arr) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let wrap_key =
                        kdf::derive_root_key(ss.as_bytes(), &hkdf_salt).context("root key")?;
                    let mut candidate = [0u8; 32];
                    for i in 0..32 {
                        candidate[i] = wrapped[i] ^ wrap_key.as_bytes()[i];
                    }
                    let mk = MasterKey::from_bytes(candidate);
                    if vault_header_mac_matches(&canonical, header.immutable_mac, &mk) {
                        return Ok(mk);
                    }
                }
                bail!("no recipient entry matched provided private key");
            } else {
                if header.kem_data.len() != CT_BYTES + 32 {
                    bail!(
                        "malformed vault header: expected {} KEM bytes",
                        CT_BYTES + 32
                    );
                }
                let ct_arr: [u8; CT_BYTES] = header.kem_data[..CT_BYTES].try_into().unwrap();
                let mut hkdf_salt = [0u8; 32];
                hkdf_salt.copy_from_slice(&header.kem_data[CT_BYTES..]);
                let ss = kem::decapsulate(&dk_arr, &ct_arr).context("KEM decapsulate")?;
                kdf::derive_root_key(ss.as_bytes(), &hkdf_salt).context("root key")
            }
        }
    }
}

fn vault_header_mac_matches(canonical: &[u8], expected_mac: [u8; 32], mk: &MasterKey) -> bool {
    let mut h = blake3::Hasher::new_keyed(mk.as_bytes());
    h.update(b"obsidianq-v1-obsv-imm");
    h.update(b"\x00");
    h.update(canonical);
    let got: [u8; 32] = h.finalize().into();
    got == expected_mac
}

fn normalize_vault_path_create(mut path: PathBuf) -> PathBuf {
    if path.extension().is_none() {
        path.set_extension("vault");
    }
    path
}

fn normalize_vault_path_use(mut path: PathBuf) -> PathBuf {
    if path.extension().is_none() {
        path.set_extension("vault");
    }
    path
}
