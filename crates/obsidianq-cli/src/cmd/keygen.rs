use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use obsidianq_core::crypto::{
    hybrid,
    kem::{self, DK_BYTES, EK_BYTES},
};

use super::{write_priv_material, write_pub_material};

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
    let (x25519_public, x25519_private) = hybrid::generate_x25519_keypair();

    write_pub_material(&args.pubkey, &ek.0, Some(&x25519_public))?;
    write_priv_material(&args.privkey, &dk.0, Some(&x25519_private))?;

    println!("Public key  -> {}", args.pubkey.display());
    println!("Private key -> {}", args.privkey.display());
    println!(
        "Key sizes: Kyber EK={} B, Kyber DK={} B, X25519 pub={} B, X25519 priv={} B",
        EK_BYTES,
        DK_BYTES,
        hybrid::X25519_PUBLIC_BYTES,
        hybrid::X25519_PRIVATE_BYTES
    );
    Ok(())
}
