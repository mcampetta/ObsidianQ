use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use clap::{Args, Subcommand};

use obsidianq_core::secure_connect::{
    compute_verify_phrase, decapsulate_b64, derive_session_key, encapsulate_to_peer_b64,
    generate_ephemeral_keypair_b64, generate_pairing_code, SessionId,
};

#[derive(Args)]
pub struct SecureConnectArgs {
    #[command(subcommand)]
    pub cmd: SecureConnectCmd,
}

#[derive(Subcommand)]
pub enum SecureConnectCmd {
    /// Create a new receive-side pairing session (ephemeral keys)
    NewSession,
    /// Encapsulate to the receiver public key
    Encapsulate(EncapsulateArgs),
    /// Decapsulate receiver-side ciphertext
    Decapsulate(DecapsulateArgs),
    /// Derive session key + verification phrase
    Derive(DeriveArgs),
}

#[derive(Args)]
pub struct EncapsulateArgs {
    #[arg(long)]
    pub peer_pub: String,
}

#[derive(Args)]
pub struct DecapsulateArgs {
    #[arg(long)]
    pub private_key: String,
    #[arg(long)]
    pub ciphertext: String,
}

#[derive(Args)]
pub struct DeriveArgs {
    #[arg(long)]
    pub shared_secret: String,
    #[arg(long)]
    pub session_id: String,
}

pub fn run(args: SecureConnectArgs) -> Result<()> {
    match args.cmd {
        SecureConnectCmd::NewSession => run_new_session(),
        SecureConnectCmd::Encapsulate(a) => run_encapsulate(a),
        SecureConnectCmd::Decapsulate(a) => run_decapsulate(a),
        SecureConnectCmd::Derive(a) => run_derive(a),
    }
}

fn run_new_session() -> Result<()> {
    let session_id = SessionId::random();
    let code = generate_pairing_code();
    let (public_key, private_key) = generate_ephemeral_keypair_b64();
    println!("session_id={}", session_id.to_hex());
    println!("code={code}");
    println!("public_key={public_key}");
    println!("private_key={private_key}");
    Ok(())
}

fn run_encapsulate(args: EncapsulateArgs) -> Result<()> {
    let (ciphertext, ss) = encapsulate_to_peer_b64(&args.peer_pub).context("encapsulate")?;
    println!("ciphertext={ciphertext}");
    println!("shared_secret={}", Base64::encode_string(&ss));
    Ok(())
}

fn run_decapsulate(args: DecapsulateArgs) -> Result<()> {
    let ss = decapsulate_b64(&args.private_key, &args.ciphertext).context("decapsulate")?;
    println!("shared_secret={}", Base64::encode_string(&ss));
    Ok(())
}

fn run_derive(args: DeriveArgs) -> Result<()> {
    let sid = SessionId::from_hex(&args.session_id).context("invalid session id")?;
    let ss = Base64::decode_vec(&args.shared_secret).context("invalid shared secret base64")?;
    if ss.len() != 32 {
        anyhow::bail!("shared secret must be 32 bytes");
    }
    let mut shared = [0u8; 32];
    shared.copy_from_slice(&ss);
    let key = derive_session_key(&shared, &sid).context("derive key")?;
    let phrase = compute_verify_phrase(&key, &sid).context("compute phrase")?;
    println!("session_key={}", Base64::encode_string(&key));
    println!("verify_phrase={phrase}");
    Ok(())
}
