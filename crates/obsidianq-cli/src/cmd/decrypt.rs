use std::fs;
use std::io::{BufRead, BufReader, BufWriter};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;
use zeroize::{Zeroize, Zeroizing};

use obsidianq_core::{
    crypto::{
        kem::{self, CT_BYTES, DK_BYTES},
        kdf::{self, Argon2Params},
    },
    format::{FileHeader, Mode},
};

use super::read_pem_priv;

#[derive(Args)]
pub struct DecryptArgs {
    /// Input .obsq file
    #[arg(long)]
    pub r#in: PathBuf,

    /// Output plaintext file
    #[arg(long)]
    pub out: PathBuf,

    /// Private (decapsulation) key for PQC mode
    #[arg(long)]
    pub privkey: Option<PathBuf>,

    /// Read password from stdin (one line). For GUI/scripted use.
    #[arg(long)]
    pub password_stdin: bool,
}

pub fn run(args: DecryptArgs) -> Result<()> {
    // Peek at the header to determine mode, then seek back.
    let mut peek = BufReader::new(fs::File::open(&args.r#in).context("open input")?);
    let header = FileHeader::read_from(&mut peek).context("parse header")?;

    let master_key = match header.mode {
        Mode::Password => {
            let password = if args.password_stdin {
                let mut raw = String::new();
                std::io::stdin().lock().read_line(&mut raw).context("read password from stdin")?;
                let pw = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned());
                raw.zeroize();
                pw
            } else {
                Zeroizing::new(
                    rpassword::prompt_password("Password: ").context("password prompt")?,
                )
            };
            if header.kem_data.len() != 32 {
                bail!("malformed header: expected 32-byte salt, got {}", header.kem_data.len());
            }
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&header.kem_data);
            kdf::derive_password_key(password.as_bytes(), &salt, &Argon2Params::default())
                .context("key derivation")?
        }
        Mode::Pqc => {
            let pk_path = args.privkey.as_ref()
                .context("--privkey required for PQC mode")?;
            let dk_raw = read_pem_priv(pk_path).context("read private key")?;
            if dk_raw.len() != DK_BYTES {
                bail!("private key is {} bytes, expected {}", dk_raw.len(), DK_BYTES);
            }
            let dk_arr: [u8; DK_BYTES] = dk_raw
                .try_into()
                .map_err(|_| anyhow::anyhow!("private key has wrong length (expected {DK_BYTES} bytes)"))?;

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
            kdf::derive_root_key(ss.as_bytes(), &hkdf_salt).context("root key derivation")?
        }
    };

    // Re-open from the start for full decrypt.
    let in_file  = fs::File::open(&args.r#in).context("open input")?;
    let out_file = fs::File::create(&args.out).context("create output")?;
    let mut reader = BufReader::new(in_file);
    let mut writer = BufWriter::new(out_file);

    let start = std::time::Instant::now();
    obsidianq_core::decrypt(&master_key, &mut reader, &mut writer).context("decryption")?;

    use std::io::Write as _;
    writer.flush().context("flush output")?;
    drop(writer);

    let elapsed = start.elapsed();
    let out_size = fs::metadata(&args.out)?.len();
    let mb_per_s = out_size as f64 / elapsed.as_secs_f64() / 1_048_576.0;
    println!("Decrypted {} bytes in {:.2?}  ({:.1} MB/s)", out_size, elapsed, mb_per_s);
    Ok(())
}
