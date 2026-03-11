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
use zeroize::{Zeroize, Zeroizing};

use obsidianq_core::{
    crypto::{
        kdf::{self, Argon2Params, MasterKey},
        kem::{self, CT_BYTES, DK_BYTES},
    },
    engine::decrypt_with_progress,
    format::{FileHeader, Mode},
};

use super::json_output::{print_json_error, print_json_success};
use super::read_priv;

const MULTI_MAGIC_V1: &[u8; 4] = b"MRK1";
const MULTI_MAGIC_V2: &[u8; 4] = b"MRK2";
const WRAP_NONCE_LEN: usize = 24;
const WRAP_CT_LEN: usize = 48; // 32-byte key + 16-byte tag
const WRAP_INFO: &[u8] = b"obsidianq-v1-mrk2-wrap";

#[derive(Args)]
pub struct DecryptArgs {
    /// Input .obsq file (required without --text)
    #[arg(long, conflicts_with = "text")]
    pub r#in: Option<PathBuf>,

    /// Output plaintext file (required without --text)
    #[arg(long, conflicts_with = "text")]
    pub out: Option<PathBuf>,

    /// Decrypt base64-encoded .obsq from stdin, write plaintext to stdout
    #[arg(long, conflicts_with_all = ["in", "out"])]
    pub text: bool,

    /// Private (decapsulation) key for PQC mode
    #[arg(long)]
    pub privkey: Option<PathBuf>,

    /// Read password from stdin (one line). For GUI/scripted use.
    #[arg(long)]
    pub password_stdin: bool,

    /// Emit machine-readable JSON response
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: DecryptArgs) -> Result<()> {
    let json = args.json;
    if json && args.text {
        print_json_error(
            "decrypt",
            "UNSUPPORTED_FORMAT",
            "--json is not supported with --text mode",
            Some("text"),
        )?;
        process::exit(2);
    }
    match run_impl(args) {
        Ok(()) => {
            if json {
                print_json_success("decrypt", serde_json::json!({ "status": "ok" }))?;
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
                print_json_error("decrypt", code, &msg, None)?;
                process::exit(if code == "INTERNAL" { 1 } else { 2 });
            }
            Err(e)
        }
    }
}

fn run_impl(args: DecryptArgs) -> Result<()> {
    if !args.text && (args.r#in.is_none() || args.out.is_none()) {
        bail!("provide --in and --out, or use --text for stdin/stdout mode");
    }

    if args.text {
        return run_text(args);
    }
    run_file(args)
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

fn run_text(args: DecryptArgs) -> Result<()> {
    // Optionally read password from stdin line 1 (before the base64 payload).
    let password_opt: Option<Zeroizing<String>> = if args.password_stdin {
        let mut raw = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut raw)
            .context("read password from stdin")?;
        let pw = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned());
        raw.zeroize();
        Some(pw)
    } else {
        None
    };

    // Read the rest of stdin as base64-encoded ciphertext.
    let mut b64 = String::new();
    std::io::stdin()
        .lock()
        .read_to_string(&mut b64)
        .context("read base64 ciphertext from stdin")?;

    use base64ct::{Base64, Encoding};
    let ciphertext = Base64::decode_vec(b64.trim()).context("invalid base64 input")?;

    // Parse header from decoded bytes to determine mode.
    let header = {
        let mut peek = std::io::Cursor::new(&ciphertext);
        FileHeader::read_from(&mut peek).context("parse header")?
    };

    let master_key = derive_master_key(&header, &args, password_opt)?;

    let mut cursor = std::io::Cursor::new(&ciphertext);
    let mut out = std::io::stdout().lock();
    obsidianq_core::decrypt(&master_key, &mut cursor, &mut out).context("decryption")?;
    Ok(())
}

fn run_file(args: DecryptArgs) -> Result<()> {
    let in_path = args.r#in.as_ref().unwrap();
    let out_path = args.out.as_ref().unwrap();

    // Peek at the header to determine mode, then re-open for full decrypt.
    let header = {
        let mut peek = BufReader::new(fs::File::open(in_path).context("open input")?);
        FileHeader::read_from(&mut peek).context("parse header")?
    };

    let master_key = derive_master_key(&header, &args, None)?;

    let in_file = fs::File::open(in_path).context("open input")?;
    let out_file = fs::File::create(out_path).context("create output")?;
    let mut reader = BufReader::new(in_file);
    let mut writer = BufWriter::new(out_file);
    let input_size = fs::metadata(in_path)?.len();
    let progress = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    const TOTAL_UNITS: u64 = 1000;
    const BASE_UNITS: u64 = 70;
    const SPAN_UNITS: u64 = 840;
    eprintln!("[PROGRESS_STAGE] op=decrypt stage=preparing");
    eprintln!(
        "[PROGRESS] op=decrypt processed={} total={}",
        BASE_UNITS, TOTAL_UNITS
    );
    let reporter = spawn_progress_reporter(
        "decrypt",
        input_size,
        BASE_UNITS,
        SPAN_UNITS,
        TOTAL_UNITS,
        Arc::clone(&progress),
        Arc::clone(&done),
    );
    eprintln!("[PROGRESS_STAGE] op=decrypt stage=decrypting");

    let start = std::time::Instant::now();
    decrypt_with_progress(
        &master_key,
        &mut reader,
        &mut writer,
        Some(progress.as_ref()),
    )
    .context("decryption")?;
    done.store(true, Ordering::Relaxed);
    let _ = reporter.join();
    eprintln!("[PROGRESS_STAGE] op=decrypt stage=finalizing");
    eprintln!("[PROGRESS] op=decrypt processed=960 total={}", TOTAL_UNITS);

    use std::io::Write as _;
    writer.flush().context("flush output")?;
    drop(writer);
    eprintln!("[PROGRESS] op=decrypt processed=1000 total={}", TOTAL_UNITS);

    let elapsed = start.elapsed();
    let out_size = fs::metadata(out_path)?.len();
    let mb_per_s = out_size as f64 / elapsed.as_secs_f64() / 1_048_576.0;
    println!(
        "Decrypted {} bytes in {:.2?}  ({:.1} MB/s)",
        out_size, elapsed, mb_per_s
    );
    Ok(())
}

/// Derive the master key from the file header, reading credential from stdin or
/// key file as appropriate.  `password_already_read` carries a password that was
/// already read from stdin (text mode only, where the password must be read
/// before the ciphertext blob).
fn derive_master_key(
    header: &FileHeader,
    args: &DecryptArgs,
    password_already_read: Option<Zeroizing<String>>,
) -> Result<obsidianq_core::crypto::kdf::MasterKey> {
    match header.mode {
        Mode::Password => {
            let password = if let Some(pw) = password_already_read {
                // Already read from stdin in text mode.
                pw
            } else if args.password_stdin {
                let mut raw = String::new();
                std::io::stdin()
                    .lock()
                    .read_line(&mut raw)
                    .context("read password from stdin")?;
                let pw = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned());
                raw.zeroize();
                pw
            } else {
                Zeroizing::new(rpassword::prompt_password("Password: ").context("password prompt")?)
            };

            if header.kem_data.len() != 32 {
                bail!(
                    "malformed header: expected 32-byte salt, got {}",
                    header.kem_data.len()
                );
            }
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&header.kem_data);
            kdf::derive_password_key(password.as_bytes(), &salt, &Argon2Params::default())
                .context("key derivation")
        }

        Mode::Pqc => {
            let pk_path = args
                .privkey
                .as_ref()
                .context("--privkey required for PQC mode")?;
            let dk_raw = read_priv(pk_path).context("read private key")?;
            if dk_raw.len() != DK_BYTES {
                bail!(
                    "private key is {} bytes, expected {}",
                    dk_raw.len(),
                    DK_BYTES
                );
            }
            let dk_arr: [u8; DK_BYTES] = dk_raw.try_into().map_err(|_| {
                anyhow::anyhow!("private key has wrong length (expected {DK_BYTES} bytes)")
            })?;

            if header.kem_data.starts_with(MULTI_MAGIC_V2) {
                if header.kem_data.len() < 4 + 2 + 32 {
                    bail!("malformed header: multi-recipient KEM data too short");
                }
                let count = u16::from_le_bytes([header.kem_data[4], header.kem_data[5]]) as usize;
                let expected = 4 + 2 + count * (CT_BYTES + WRAP_NONCE_LEN + WRAP_CT_LEN) + 32;
                if header.kem_data.len() != expected {
                    bail!(
                        "malformed header: expected {} bytes of multi-recipient KEM data, got {}",
                        expected,
                        header.kem_data.len()
                    );
                }
                let salt_off = expected - 32;
                let mut hkdf_salt = [0u8; 32];
                hkdf_salt.copy_from_slice(&header.kem_data[salt_off..]);
                let canonical = header.canonical_bytes_for_mac();
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
                    let wrap_key = kdf::derive_root_key(ss.as_bytes(), &hkdf_salt)
                        .context("root key derivation")?;
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
                    if header_mac_matches(header, &canonical, &mk) {
                        return Ok(mk);
                    }
                }
                bail!("no recipient entry matched provided private key");
            } else if header.kem_data.starts_with(MULTI_MAGIC_V1) {
                if header.kem_data.len() < 4 + 2 + 32 {
                    bail!("malformed header: multi-recipient KEM data too short");
                }
                let count = u16::from_le_bytes([header.kem_data[4], header.kem_data[5]]) as usize;
                let expected = 4 + 2 + count * (CT_BYTES + 32) + 32;
                if header.kem_data.len() != expected {
                    bail!(
                        "malformed header: expected {} bytes of multi-recipient KEM data, got {}",
                        expected,
                        header.kem_data.len()
                    );
                }
                let salt_off = expected - 32;
                let mut hkdf_salt = [0u8; 32];
                hkdf_salt.copy_from_slice(&header.kem_data[salt_off..]);
                let canonical = header.canonical_bytes_for_mac();
                let mut off = 6usize;
                for _ in 0..count {
                    let ct_arr: [u8; CT_BYTES] = header.kem_data[off..off + CT_BYTES]
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("KEM ciphertext slice has wrong length"))?;
                    off += CT_BYTES;
                    let wrapped = &header.kem_data[off..off + 32];
                    off += 32;
                    let ss = match kem::decapsulate(&dk_arr, &ct_arr) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let wrap_key = kdf::derive_root_key(ss.as_bytes(), &hkdf_salt)
                        .context("root key derivation")?;
                    let mut candidate = [0u8; 32];
                    for i in 0..32 {
                        candidate[i] = wrapped[i] ^ wrap_key.as_bytes()[i];
                    }
                    let mk = MasterKey::from_bytes(candidate);
                    if header_mac_matches(header, &canonical, &mk) {
                        return Ok(mk);
                    }
                }
                bail!("no recipient entry matched provided private key");
            } else {
                if header.kem_data.len() != CT_BYTES + 32 {
                    bail!(
                        "malformed header: expected {} bytes of KEM data, got {}",
                        CT_BYTES + 32,
                        header.kem_data.len()
                    );
                }
                let ct_arr: [u8; CT_BYTES] = header.kem_data[..CT_BYTES]
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("KEM ciphertext slice has wrong length"))?;
                let mut hkdf_salt = [0u8; 32];
                hkdf_salt.copy_from_slice(&header.kem_data[CT_BYTES..]);

                let ss = kem::decapsulate(&dk_arr, &ct_arr).context("KEM decapsulation")?;
                kdf::derive_root_key(ss.as_bytes(), &hkdf_salt).context("root key derivation")
            }
        }
    }
}

fn header_mac_matches(header: &FileHeader, canonical: &[u8], mk: &MasterKey) -> bool {
    // Mirrors obsidianq_core::engine DOMAIN_HEADER MAC construction:
    // BLAKE3-keyed(K_master, "obsidianq-v1-header" || "\x00" || canonical_header)
    let mut h = blake3::Hasher::new_keyed(mk.as_bytes());
    h.update(b"obsidianq-v1-header");
    h.update(b"\x00");
    h.update(canonical);
    let got: [u8; 32] = h.finalize().into();
    got == header.mac
}
