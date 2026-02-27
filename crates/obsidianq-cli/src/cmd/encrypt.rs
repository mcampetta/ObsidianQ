use std::fs;
use std::io::{BufReader, BufWriter, BufRead};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use obsidianq_core::{
    crypto::{
        kem::{self, CT_BYTES, EK_BYTES},
        kdf::{self, Argon2Params},
    },
    engine::{EncryptParams, DEFAULT_CHUNK_SIZE},
    format::{Mode, SuiteId},
};

use super::read_pub;

#[derive(Args)]
pub struct EncryptArgs {
    /// Input plaintext file
    #[arg(long)]
    pub r#in: PathBuf,

    /// Output .obsq file
    #[arg(long)]
    pub out: PathBuf,

    /// Encrypt with password (interactive prompt)
    #[arg(long, conflicts_with_all = ["pubkey", "password_stdin"])]
    pub password: bool,

    /// Read password from stdin (one line). For GUI/scripted use.
    #[arg(long, conflicts_with_all = ["password", "pubkey"])]
    pub password_stdin: bool,

    /// Recipient ML-KEM-768 public key file (.bin raw bytes by default; .pem also supported)
    #[arg(long, conflicts_with_all = ["password", "password_stdin"])]
    pub pubkey: Option<PathBuf>,

    /// Cipher suite [xchacha20 | aesgcm]
    #[arg(long, default_value = "xchacha20")]
    pub suite: String,

    /// Compress plaintext with zstd before encrypting
    #[arg(long)]
    pub compress: bool,

    /// Chunk size in bytes (default 1 MiB)
    #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
    pub chunk_size: u32,
}

pub fn run(args: EncryptArgs) -> Result<()> {
    if !args.password && !args.password_stdin && args.pubkey.is_none() {
        bail!("provide one of --password, --password-stdin, or --pubkey <path>");
    }

    let suite = parse_suite(&args.suite)?;

    // Generate random file ID.
    let mut file_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut file_id);

    let (master_key, mode, kem_data) = if args.password || args.password_stdin {
        // Password mode: derive master key from Argon2id.
        let password = if args.password_stdin {
            // Read one line from stdin; GUI passes password this way.
            let mut raw = String::new();
            std::io::stdin().lock().read_line(&mut raw).context("read password from stdin")?;
            let pw = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned());
            raw.zeroize();
            pw
        } else {
            let pw = Zeroizing::new(
                rpassword::prompt_password("Password: ").context("password prompt")?,
            );
            let confirm = Zeroizing::new(
                rpassword::prompt_password("Confirm  : ").context("confirm prompt")?,
            );
            if *pw != *confirm {
                bail!("passwords do not match");
            }
            pw
        };

        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let mk = kdf::derive_password_key(password.as_bytes(), &salt, &Argon2Params::default())
            .context("key derivation")?;

        (mk, Mode::Password, salt.to_vec())
    } else {
        // PQC mode: encapsulate to recipient public key.
        let pk_path = args.pubkey.as_ref().unwrap();
        let pk_raw = read_pub(pk_path).context("read public key")?;

        if pk_raw.len() != EK_BYTES {
            bail!("public key is {} bytes, expected {}", pk_raw.len(), EK_BYTES);
        }
        let ek_arr: [u8; EK_BYTES] = pk_raw.try_into().unwrap();

        let (ct, ss) = kem::encapsulate(&ek_arr).context("KEM encapsulation")?;

        // HKDF salt (random, stored alongside KEM ciphertext).
        let mut hkdf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hkdf_salt);

        let mk = kdf::derive_root_key(ss.as_bytes(), &hkdf_salt).context("root key derivation")?;

        // kem_data = KEM ciphertext (1088 B) || HKDF salt (32 B)
        let mut kem_data = Vec::with_capacity(CT_BYTES + 32);
        kem_data.extend_from_slice(&ct);
        kem_data.extend_from_slice(&hkdf_salt);

        (mk, Mode::Pqc, kem_data)
    };

    let in_file  = fs::File::open(&args.r#in).context("open input")?;
    let out_file = fs::File::create(&args.out).context("create output")?;
    let mut reader = BufReader::new(in_file);
    let mut writer = BufWriter::new(out_file);

    let params = EncryptParams {
        master_key,
        kem_data,
        mode,
        suite,
        chunk_size: args.chunk_size,
        compress: args.compress,
        file_id,
    };

    let start = std::time::Instant::now();
    let n_chunks = obsidianq_core::encrypt(params, &mut reader, &mut writer)
        .context("encryption")?;

    // Flush before reading metadata so the file size is accurate.
    use std::io::Write as _;
    writer.flush().context("flush output")?;
    drop(writer);

    let input_size = fs::metadata(&args.r#in)?.len();
    let output_size = fs::metadata(&args.out)?.len();
    let elapsed = start.elapsed();
    let mb_per_s = input_size as f64 / elapsed.as_secs_f64() / 1_048_576.0;

    println!("Encrypted {} chunk(s)", n_chunks);
    println!("  Input : {} bytes", input_size);
    println!("  Output: {} bytes", output_size);
    println!("  Time  : {:.2?}  ({:.1} MB/s)", elapsed, mb_per_s);
    Ok(())
}

fn parse_suite(s: &str) -> Result<SuiteId> {
    match s {
        "xchacha20" => Ok(SuiteId::XChaCha20Poly1305),
        "aesgcm"    => Ok(SuiteId::Aes256Gcm),
        other       => bail!("unknown suite '{}' â€” use 'xchacha20' or 'aesgcm'", other),
    }
}

