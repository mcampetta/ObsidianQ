use std::io::BufReader;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use obsidianq_core::format::{FileHeader, Mode, SuiteId, flags};

#[derive(Args)]
pub struct InspectArgs {
    /// The .obsq file to inspect
    pub file: PathBuf,
}

pub fn run(args: InspectArgs) -> Result<()> {
    let f = std::fs::File::open(&args.file).context("open file")?;
    let mut r = BufReader::new(f);
    let h = FileHeader::read_from(&mut r).context("parse header")?;

    println!("┌─ ObsidianQ File: {}", args.file.display());
    println!("│  Version   : {}", h.version);
    println!("│  Mode      : {}", match h.mode {
        Mode::Password => "Password (Argon2id)",
        Mode::Pqc      => "PQC (ML-KEM-768)",
    });
    println!("│  Suite     : {}", match h.suite {
        SuiteId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        SuiteId::Aes256Gcm         => "AES-256-GCM",
    });
    println!("│  Chunk size: {} KiB ({} bytes)", h.chunk_size / 1024, h.chunk_size);
    println!("│  Flags     :");
    println!("│    Compressed: {}", h.flags & flags::COMPRESSED != 0);
    println!("│  File ID   : {}", hex::encode(h.file_id));
    println!("│  KEM data  : {} bytes", h.kem_data.len());
    println!("│  Header MAC: {}", hex::encode(h.mac));
    println!("└─ (body not verified — provide key to decrypt)");
    Ok(())
}
