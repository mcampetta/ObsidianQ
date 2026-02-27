use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use obsidianq_core::crypto::kem::{self, EK_BYTES, DK_BYTES};

use super::{write_pem_priv, write_pem_pub};

#[derive(Args)]
pub struct KeygenArgs {
    /// Output path for the public (encapsulation) key
    #[arg(long, default_value = "obsidianq_pub.pem")]
    pub pubkey: PathBuf,

    /// Output path for the private (decapsulation) key
    #[arg(long, default_value = "obsidianq_priv.pem")]
    pub privkey: PathBuf,
}

pub fn run(args: KeygenArgs) -> Result<()> {
    let (ek, dk) = kem::generate_keypair();

    write_pem_pub(&args.pubkey, ek.0.as_ref())?;
    write_pem_priv(&args.privkey, dk.0.as_ref())?;

    println!("Public key  → {}", args.pubkey.display());
    println!("Private key → {}", args.privkey.display());
    println!("Key sizes: EK={} B, DK={} B", EK_BYTES, DK_BYTES);
    Ok(())
}
