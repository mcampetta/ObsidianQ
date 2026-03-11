use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use std::process;

use anyhow::{bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use clap::Args;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use obsidianq_core::{
    crypto::{
        kdf::{self, Argon2Params, MasterKey},
        kem::{self, CT_BYTES, EK_BYTES},
    },
    engine::{encrypt_with_progress, EncryptParams, DEFAULT_CHUNK_SIZE},
    format::{Mode, SuiteId},
};

use super::json_output::{print_json_error, print_json_success};
use super::read_pub;

const MULTI_MAGIC_V2: &[u8; 4] = b"MRK2";
const WRAP_NONCE_LEN: usize = 24;
const WRAP_CT_LEN: usize = 48; // 32-byte key + 16-byte tag
const WRAP_INFO: &[u8] = b"obsidianq-v1-mrk2-wrap";

#[derive(Args)]
pub struct EncryptArgs {
    /// Input plaintext file (required without --text)
    #[arg(long, conflicts_with = "text")]
    pub r#in: Option<PathBuf>,

    /// Output .obsq file (required without --text)
    #[arg(long, conflicts_with = "text")]
    pub out: Option<PathBuf>,

    /// Encrypt text from stdin, emit base64-encoded .obsq to stdout
    #[arg(long, conflicts_with_all = ["in", "out"])]
    pub text: bool,

    /// Encrypt with password (interactive prompt)
    #[arg(long, conflicts_with_all = ["pubkey", "password_stdin"])]
    pub password: bool,

    /// Read password from stdin (one line). For GUI/scripted use.
    #[arg(long, conflicts_with_all = ["password", "pubkey"])]
    pub password_stdin: bool,

    /// Recipient ML-KEM-768 public key file (.bin raw bytes by default; .pem also supported)
    /// Repeat --pubkey to encrypt once for multiple recipients in a single .obsq output.
    #[arg(long = "pubkey", conflicts_with_all = ["password", "password_stdin"])]
    pub pubkey: Vec<PathBuf>,

    /// Cipher suite [xchacha20 | aesgcm]
    #[arg(long, default_value = "xchacha20")]
    pub suite: String,

    /// Compress plaintext with zstd before encrypting
    #[arg(long)]
    pub compress: bool,

    /// Chunk size in bytes (default 1 MiB)
    #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
    pub chunk_size: u32,

    /// Emit machine-readable JSON response
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: EncryptArgs) -> Result<()> {
    let json = args.json;
    if json && args.text {
        print_json_error(
            "encrypt",
            "UNSUPPORTED_FORMAT",
            "--json is not supported with --text mode",
            Some("text"),
        )?;
        process::exit(2);
    }
    match run_impl(args) {
        Ok(()) => {
            if json {
                print_json_success("encrypt", serde_json::json!({ "status": "ok" }))?;
            }
            Ok(())
        }
        Err(e) => {
            if json {
                let msg = e.to_string();
                let code = if msg.contains("password") {
                    "PASSWORD_MISSING"
                } else if msg.contains("not found") {
                    "INPUT_NOT_FOUND"
                } else {
                    "INTERNAL"
                };
                print_json_error("encrypt", code, &msg, None)?;
                process::exit(if code == "INTERNAL" { 1 } else { 2 });
            }
            Err(e)
        }
    }
}

fn run_impl(args: EncryptArgs) -> Result<()> {
    if !args.password && !args.password_stdin && args.pubkey.is_empty() {
        bail!("provide one of --password, --password-stdin, or --pubkey <path>");
    }
    if !args.text && (args.r#in.is_none() || args.out.is_none()) {
        bail!("provide --in and --out, or use --text for stdin/stdout mode");
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
            std::io::stdin()
                .lock()
                .read_line(&mut raw)
                .context("read password from stdin")?;
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
        if args.pubkey.len() == 1 {
            let pk_raw = read_pub(&args.pubkey[0]).context("read public key")?;
            if pk_raw.len() != EK_BYTES {
                bail!(
                    "public key is {} bytes, expected {}",
                    pk_raw.len(),
                    EK_BYTES
                );
            }
            let ek_arr: [u8; EK_BYTES] = pk_raw.try_into().unwrap();
            let (ct, ss) = kem::encapsulate(&ek_arr).context("KEM encapsulation")?;
            let mut hkdf_salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut hkdf_salt);
            let mk =
                kdf::derive_root_key(ss.as_bytes(), &hkdf_salt).context("root key derivation")?;
            let mut kem_data = Vec::with_capacity(CT_BYTES + 32);
            kem_data.extend_from_slice(&ct);
            kem_data.extend_from_slice(&hkdf_salt);
            (mk, Mode::Pqc, kem_data)
        } else {
            let mut hkdf_salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut hkdf_salt);
            let mut master_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut master_bytes);
            let mk = MasterKey::from_bytes(master_bytes);

            let count = args.pubkey.len();
            if count > u16::MAX as usize {
                bail!("too many recipients: {count}");
            }

            let total_len = 4 + 2 + count * (CT_BYTES + WRAP_NONCE_LEN + WRAP_CT_LEN) + 32;
            if total_len > u16::MAX as usize {
                bail!(
                    "too many recipients for file header format ({} bytes > 65535)",
                    total_len
                );
            }

            let mut kem_data = Vec::with_capacity(total_len);
            kem_data.extend_from_slice(MULTI_MAGIC_V2);
            kem_data.extend_from_slice(&(count as u16).to_le_bytes());

            for (idx, path) in args.pubkey.iter().enumerate() {
                let pk_raw = read_pub(path)
                    .with_context(|| format!("read public key {}", path.display()))?;
                if pk_raw.len() != EK_BYTES {
                    bail!(
                        "public key {} is {} bytes, expected {}",
                        path.display(),
                        pk_raw.len(),
                        EK_BYTES
                    );
                }
                let ek_arr: [u8; EK_BYTES] = pk_raw.try_into().unwrap();
                let (ct, ss) = kem::encapsulate(&ek_arr).context("KEM encapsulation")?;
                let wrap_key = kdf::derive_root_key(ss.as_bytes(), &hkdf_salt)
                    .context("root key derivation")?;
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
                            msg: mk.as_bytes(),
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
            (mk, Mode::Pqc, kem_data)
        }
    };

    let params = EncryptParams {
        master_key,
        kem_data,
        mode,
        suite,
        chunk_size: args.chunk_size,
        compress: args.compress,
        file_id,
    };

    if args.text {
        // Read plaintext from stdin into memory (password line already consumed above).
        let mut plaintext = Vec::new();
        std::io::stdin()
            .lock()
            .read_to_end(&mut plaintext)
            .context("read plaintext from stdin")?;

        // Encrypt into an in-memory Vec.
        let mut ciphertext = Vec::new();
        let mut cursor = std::io::Cursor::new(&plaintext);
        let n_chunks =
            obsidianq_core::encrypt(params, &mut cursor, &mut ciphertext).context("encryption")?;

        // Base64-encode and write to stdout (stdout must stay clean for piping).
        use base64ct::{Base64, Encoding};
        let b64 = Base64::encode_string(&ciphertext);
        println!("{}", b64);
        eprintln!(
            "Encrypted {} chunk(s), {} \u{2192} {} bytes (base64)",
            n_chunks,
            plaintext.len(),
            b64.len()
        );
        return Ok(());
    }

    // File mode.
    let in_path = args.r#in.as_ref().unwrap();
    let out_path = args.out.as_ref().unwrap();
    let in_file = fs::File::open(in_path).context("open input")?;
    let out_file = fs::File::create(out_path).context("create output")?;
    let mut reader = BufReader::new(in_file);
    let mut writer = BufWriter::new(out_file);
    let input_size = fs::metadata(in_path)?.len();
    let progress = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    const TOTAL_UNITS: u64 = 1000;
    const BASE_UNITS: u64 = 80;
    const SPAN_UNITS: u64 = 820;
    eprintln!("[PROGRESS_STAGE] op=encrypt stage=preparing");
    eprintln!(
        "[PROGRESS] op=encrypt processed={} total={}",
        BASE_UNITS, TOTAL_UNITS
    );
    let reporter = spawn_progress_reporter(
        "encrypt",
        input_size,
        BASE_UNITS,
        SPAN_UNITS,
        TOTAL_UNITS,
        Arc::clone(&progress),
        Arc::clone(&done),
    );
    eprintln!("[PROGRESS_STAGE] op=encrypt stage=encrypting");

    let start = std::time::Instant::now();
    let n_chunks = encrypt_with_progress(params, &mut reader, &mut writer, Some(progress.as_ref()))
        .context("encryption")?;
    done.store(true, Ordering::Relaxed);
    let _ = reporter.join();
    eprintln!("[PROGRESS_STAGE] op=encrypt stage=finalizing");
    eprintln!("[PROGRESS] op=encrypt processed=960 total={}", TOTAL_UNITS);

    // Flush before reading metadata so the file size is accurate.
    use std::io::Write as _;
    writer.flush().context("flush output")?;
    drop(writer);
    eprintln!("[PROGRESS] op=encrypt processed=1000 total={}", TOTAL_UNITS);

    let output_size = fs::metadata(out_path)?.len();
    let elapsed = start.elapsed();
    let mb_per_s = input_size as f64 / elapsed.as_secs_f64() / 1_048_576.0;

    println!("Encrypted {} chunk(s)", n_chunks);
    println!("  Input : {} bytes", input_size);
    println!("  Output: {} bytes", output_size);
    println!("  Time  : {:.2?}  ({:.1} MB/s)", elapsed, mb_per_s);
    Ok(())
}

fn spawn_progress_reporter(
    op: &'static str,
    total_bytes: u64,
    base_units: u64,
    span_units: u64,
    total_units: u64,
    progress: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            let raw = progress.load(Ordering::Relaxed).min(total_bytes);
            let processed = if total_bytes > 0 {
                base_units + ((raw.saturating_mul(span_units)) / total_bytes)
            } else {
                base_units
            };
            eprintln!(
                "[PROGRESS] op={} processed={} total={}",
                op, processed, total_units
            );
            thread::sleep(Duration::from_millis(200));
        }
        let raw = progress.load(Ordering::Relaxed).min(total_bytes);
        let processed = if total_bytes > 0 {
            base_units + ((raw.saturating_mul(span_units)) / total_bytes)
        } else {
            base_units
        };
        eprintln!(
            "[PROGRESS] op={} processed={} total={}",
            op, processed, total_units
        );
    })
}

fn parse_suite(s: &str) -> Result<SuiteId> {
    match s {
        "xchacha20" => Ok(SuiteId::XChaCha20Poly1305),
        "aesgcm" => Ok(SuiteId::Aes256Gcm),
        other => bail!(
            "unknown suite '{}' \u{2014} use 'xchacha20' or 'aesgcm'",
            other
        ),
    }
}
