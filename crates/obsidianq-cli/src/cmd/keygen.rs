use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use obsidianq_core::crypto::kem::{self, DK_BYTES, EK_BYTES};

use super::{write_priv, write_pub};

#[derive(Args)]
pub struct KeygenArgs {
    /// Output path for the public (encapsulation) key.
    ///
    /// Use .bin for raw key bytes (default). Use .pem for wrapped Base64 PEM.
    #[arg(long, default_value = "obsidianq_pub.bin")]
    pub pubkey: PathBuf,

    /// Output path for the private (decapsulation) key.
    ///
    /// Use .bin for raw key bytes (default). Use .pem for wrapped Base64 PEM.
    #[arg(long, default_value = "obsidianq_priv.bin")]
    pub privkey: PathBuf,
}

pub fn run(args: KeygenArgs) -> Result<()> {
    let (ek, dk) = kem::generate_keypair();

    write_pub(&args.pubkey, ek.0.as_ref())?;
    write_priv(&args.privkey, dk.0.as_ref())?;

    println!("Public key  -> {}", args.pubkey.display());
    println!("Private key -> {}", args.privkey.display());
    println!("Key sizes: EK={} B, DK={} B", EK_BYTES, DK_BYTES);
    Ok(())
}
