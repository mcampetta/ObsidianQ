use std::io::BufReader;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use obsidianq_core::format::{flags, FileHeader, Mode, SuiteId};

const MULTI_MAGIC_V1: &[u8; 4] = b"MRK1";
const MULTI_MAGIC_V2: &[u8; 4] = b"MRK2";
const MULTI_MAGIC_V3: &[u8; 4] = b"MRK3";

#[derive(Args)]
pub struct InspectArgs {
    /// The .obsq file to inspect
    pub file: PathBuf,
}

pub fn run(args: InspectArgs) -> Result<()> {
    let f = std::fs::File::open(&args.file).context("open file")?;
    let mut r = BufReader::new(f);
    let h = FileHeader::read_from(&mut r).context("parse header")?;

    println!("ObsidianQ File: {}", args.file.display());
    println!("  Version   : {}", h.version);
    println!(
        "  Mode      : {}",
        match h.mode {
            Mode::Password => "Password (Argon2id)",
            Mode::Pqc => inspect_recipient_mode(&h),
        }
    );
    println!(
        "  Suite     : {}",
        match h.suite {
            SuiteId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            SuiteId::Aes256Gcm => "AES-256-GCM",
        }
    );
    println!(
        "  Chunk size: {} KiB ({} bytes)",
        h.chunk_size / 1024,
        h.chunk_size
    );
    println!("  Flags     :");
    println!("    Compressed: {}", h.flags & flags::COMPRESSED != 0);
    println!("  File ID   : {}", hex::encode(h.file_id));
    println!("  KEM data  : {} bytes", h.kem_data.len());
    println!("  Header MAC: {}", hex::encode(h.mac));
    println!("  (body not verified - provide key to decrypt)");
    Ok(())
}

fn inspect_recipient_mode(h: &FileHeader) -> &'static str {
    if h.kem_data.starts_with(MULTI_MAGIC_V3) {
        if h.kem_data.len() >= 6 {
            let count = u16::from_le_bytes([h.kem_data[4], h.kem_data[5]]) as usize;
            if count > 1 {
                "Multi-Recipient Hybrid"
            } else {
                "Hybrid Contact"
            }
        } else {
            "Hybrid Contact"
        }
    } else if h.kem_data.starts_with(MULTI_MAGIC_V2)
        || h.kem_data.starts_with(MULTI_MAGIC_V1)
        || h.kem_data.len() > 32
    {
        "Legacy Contact"
    } else {
        "Password (Argon2id)"
    }
}
