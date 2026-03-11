use std::path::{Path, PathBuf};
use std::process;

use anyhow::{bail, Context, Result};
use base64ct::{Base64, Encoding};
use clap::{Args, Subcommand};
use rand::RngCore;
use serde::Serialize;

use obsidianq_core::{
    crypto::{
        aead, kdf,
        kem::{self, CT_BYTES, DK_BYTES, EK_BYTES},
    },
    format::SuiteId,
};

use super::json_output::{print_json_error, print_json_success};
use super::{read_priv, read_pub};

const PACKET_MAGIC: &[u8; 8] = b"OBSQX1\0\0";
const PACKET_VERSION: u16 = 1;
const EXCHANGE_SALT: &[u8] = b"obsidianq-exchange-v1-salt";
const EXCHANGE_AAD_PREFIX: &[u8] = b"obsidianq-exchange-v1-data";

#[derive(Args)]
pub struct ExchangeArgs {
    /// Emit machine-readable JSON response
    #[arg(long)]
    pub json: bool,

    #[command(subcommand)]
    pub cmd: ExchangeCmd,
}

#[derive(Subcommand)]
pub enum ExchangeCmd {
    /// Encrypt a file into an .obsqx exchange packet for a recipient public key
    Send(SendArgs),
    /// Decrypt an .obsqx exchange packet using a private key
    Recv(RecvArgs),
    /// Inspect an .obsqx packet without decrypting payload
    Inspect(InspectArgs),
    /// Print a stable fingerprint for a key file
    Fingerprint(FingerprintArgs),
}

#[derive(Args)]
pub struct SendArgs {
    /// Input plaintext file to send
    #[arg(long = "in")]
    pub input: PathBuf,
    /// Output .obsqx packet path
    #[arg(long)]
    pub out: PathBuf,
    /// Recipient public key (.bin/.pem)
    #[arg(long)]
    pub pubkey: PathBuf,
    /// Cipher suite: xchacha20 (default) or aesgcm
    #[arg(long, default_value = "xchacha20", value_parser = ["xchacha20", "aesgcm"])]
    pub suite: String,
    /// Optional sender public key (.bin/.pem) to embed for recipient verification
    #[arg(long)]
    pub sender_pubkey: Option<PathBuf>,
}

#[derive(Args)]
pub struct RecvArgs {
    /// Input .obsqx packet
    #[arg(long = "in")]
    pub input: PathBuf,
    /// Recipient private key (.bin/.pem)
    #[arg(long)]
    pub privkey: PathBuf,
    /// Output directory for decrypted file
    #[arg(long)]
    pub out_dir: PathBuf,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Input .obsqx packet
    #[arg(long = "in")]
    pub input: PathBuf,
}

#[derive(Args)]
pub struct FingerprintArgs {
    /// Key file (.bin/.pem), public or private
    #[arg(long)]
    pub key: PathBuf,
}

pub fn run(args: ExchangeArgs) -> Result<()> {
    let json = args.json;
    if json {
        return run_json(args);
    }
    match args.cmd {
        ExchangeCmd::Send(a) => {
            let out = run_send(a)?;
            println!("Wrote packet: {out}");
            Ok(())
        }
        ExchangeCmd::Recv(a) => {
            let out = run_recv(a)?;
            println!("Decrypted file: {out}");
            Ok(())
        }
        ExchangeCmd::Inspect(a) => {
            let info = run_inspect(a)?;
            print!("{}", format_inspect_legacy(&info));
            Ok(())
        }
        ExchangeCmd::Fingerprint(a) => {
            let fp = run_fingerprint(a)?;
            println!("{fp}");
            Ok(())
        }
    }
}

fn run_json(args: ExchangeArgs) -> Result<()> {
    let command_name = match args.cmd {
        ExchangeCmd::Send(_) => "exchange.send",
        ExchangeCmd::Recv(_) => "exchange.recv",
        ExchangeCmd::Inspect(_) => "exchange.inspect",
        ExchangeCmd::Fingerprint(_) => "exchange.fingerprint",
    };

    let result = match args.cmd {
        ExchangeCmd::Send(a) => run_send(a).map(|out| serde_json::json!({ "output_path": out })),
        ExchangeCmd::Recv(a) => run_recv(a).map(|out| serde_json::json!({ "output_path": out })),
        ExchangeCmd::Inspect(a) => serde_json::to_value(run_inspect(a)?).map_err(Into::into),
        ExchangeCmd::Fingerprint(a) => run_fingerprint(a).map(|fp| serde_json::json!({ "fingerprint": fp })),
    };

    match result {
        Ok(data) => print_json_success(command_name, data),
        Err(e) => {
            let msg = e.to_string();
            let code = if msg.contains("not found") {
                "INPUT_NOT_FOUND"
            } else if msg.contains("private key") || msg.contains("public key") {
                "OUTPUT_INVALID"
            } else {
                "INTERNAL"
            };
            print_json_error(command_name, code, &msg, None)?;
            process::exit(if code == "INTERNAL" { 1 } else { 2 });
        }
    }
}

#[derive(Debug, Serialize)]
struct ExchangeInspectData {
    filename: String,
    suite: String,
    payload_ct_len: usize,
    sender_fingerprint: Option<String>,
}

fn format_inspect_legacy(info: &ExchangeInspectData) -> String {
    format!(
        "filename={}\nsuite={}\npayload_ct_len={}\nsender_fingerprint={}\n",
        info.filename,
        info.suite,
        info.payload_ct_len,
        info.sender_fingerprint.clone().unwrap_or_default()
    )
}

fn run_send(args: SendArgs) -> Result<String> {
    let suite = parse_suite(&args.suite)?;
    let payload = std::fs::read(&args.input)
        .with_context(|| format!("read input {}", args.input.display()))?;
    let filename = args
        .input
        .file_name()
        .and_then(|n| n.to_str())
        .context("input file must have a valid UTF-8 filename")?;

    let pk_raw =
        read_pub(&args.pubkey).with_context(|| format!("read pubkey {}", args.pubkey.display()))?;
    let pk = to_fixed::<EK_BYTES>(&pk_raw, "public key")?;
    let (kem_ct, ss) = kem::encapsulate(&pk).context("encapsulate")?;

    let master = kdf::derive_root_key(ss.as_bytes(), EXCHANGE_SALT).context("derive root key")?;
    let header_hash = [0u8; 32];
    let chunk_key = kdf::derive_chunk_key(&master, &header_hash, 0).context("derive chunk key")?;
    let mut file_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut file_id);

    let mut aad = Vec::with_capacity(EXCHANGE_AAD_PREFIX.len() + filename.len());
    aad.extend_from_slice(EXCHANGE_AAD_PREFIX);
    aad.extend_from_slice(filename.as_bytes());
    let ct = aead::encrypt_chunk(suite, &chunk_key, &file_id, 0, &payload, &aad)
        .context("encrypt payload")?;

    let packet = ExchangePacket {
        suite,
        filename: filename.to_string(),
        file_id,
        kem_ct,
        sender_pubkey: if let Some(path) = args.sender_pubkey.as_ref() {
            Some(read_pub(path).with_context(|| format!("read sender pubkey {}", path.display()))?)
        } else {
            None
        },
        payload_ct: ct,
    };
    write_packet(&args.out, &packet)?;
    Ok(args.out.display().to_string())
}

fn run_recv(args: RecvArgs) -> Result<String> {
    let packet = read_packet(&args.input)?;

    let sk_raw = read_priv(&args.privkey)
        .with_context(|| format!("read privkey {}", args.privkey.display()))?;
    let sk = to_fixed::<DK_BYTES>(&sk_raw, "private key")?;
    let ss = kem::decapsulate(&sk, &packet.kem_ct).context("decapsulate")?;
    let master = kdf::derive_root_key(ss.as_bytes(), EXCHANGE_SALT).context("derive root key")?;
    let header_hash = [0u8; 32];
    let chunk_key = kdf::derive_chunk_key(&master, &header_hash, 0).context("derive chunk key")?;

    let mut aad = Vec::with_capacity(EXCHANGE_AAD_PREFIX.len() + packet.filename.len());
    aad.extend_from_slice(EXCHANGE_AAD_PREFIX);
    aad.extend_from_slice(packet.filename.as_bytes());
    let pt = aead::decrypt_chunk(
        packet.suite,
        &chunk_key,
        &packet.file_id,
        0,
        &packet.payload_ct,
        &aad,
    )
    .context("decrypt payload")?;

    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create output dir {}", args.out_dir.display()))?;
    let out_path = args.out_dir.join(sanitize_filename(&packet.filename));
    std::fs::write(&out_path, pt)
        .with_context(|| format!("write output {}", out_path.display()))?;
    Ok(out_path.display().to_string())
}

fn run_fingerprint(args: FingerprintArgs) -> Result<String> {
    let bytes =
        std::fs::read(&args.key).with_context(|| format!("read key {}", args.key.display()))?;
    let decoded = if let Ok(pubk) = read_pub(&args.key) {
        pubk
    } else if let Ok(privk) = read_priv(&args.key) {
        privk
    } else {
        bytes
    };
    let hash = blake3::hash(&decoded);
    Ok(Base64::encode_string(hash.as_bytes()))
}

fn run_inspect(args: InspectArgs) -> Result<ExchangeInspectData> {
    let packet = read_packet(&args.input)?;
    let suite = match packet.suite {
        SuiteId::XChaCha20Poly1305 => "xchacha20",
        SuiteId::Aes256Gcm => "aesgcm",
    }
    .to_string();
    let sender_fingerprint = packet
        .sender_pubkey
        .as_ref()
        .map(|spk| Base64::encode_string(blake3::hash(spk).as_bytes()));
    Ok(ExchangeInspectData {
        filename: packet.filename,
        suite,
        payload_ct_len: packet.payload_ct.len(),
        sender_fingerprint,
    })
}

struct ExchangePacket {
    suite: SuiteId,
    filename: String,
    file_id: [u8; 16],
    kem_ct: [u8; CT_BYTES],
    sender_pubkey: Option<Vec<u8>>,
    payload_ct: Vec<u8>,
}

fn write_packet(path: &Path, packet: &ExchangePacket) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create output dir {}", parent.display()))?;
        }
    }
    let sender_len = packet.sender_pubkey.as_ref().map_or(0usize, |v| v.len());
    let mut out = Vec::with_capacity(
        8 + 2
            + 1
            + 1
            + 2
            + packet.filename.len()
            + 16
            + CT_BYTES
            + 4
            + sender_len
            + 8
            + packet.payload_ct.len(),
    );
    out.extend_from_slice(PACKET_MAGIC);
    // v2 adds sender_pubkey_len + sender_pubkey bytes
    out.extend_from_slice(&2u16.to_le_bytes());
    out.push(packet.suite as u8);
    out.push(0);
    out.extend_from_slice(&(packet.filename.len() as u16).to_le_bytes());
    out.extend_from_slice(packet.filename.as_bytes());
    out.extend_from_slice(&packet.file_id);
    out.extend_from_slice(&packet.kem_ct);
    out.extend_from_slice(&(sender_len as u32).to_le_bytes());
    if let Some(spk) = packet.sender_pubkey.as_ref() {
        out.extend_from_slice(spk);
    }
    out.extend_from_slice(&(packet.payload_ct.len() as u64).to_le_bytes());
    out.extend_from_slice(&packet.payload_ct);
    std::fs::write(path, out).with_context(|| format!("write packet {}", path.display()))?;
    Ok(())
}

fn read_packet(path: &Path) -> Result<ExchangePacket> {
    let bytes = std::fs::read(path).with_context(|| format!("read packet {}", path.display()))?;
    let mut off = 0usize;

    if bytes.len() < 8 + 2 + 1 + 1 + 2 + 16 + CT_BYTES + 8 {
        bail!("packet too short");
    }
    if &bytes[off..off + 8] != PACKET_MAGIC {
        bail!("invalid packet magic");
    }
    off += 8;

    let version = u16::from_le_bytes([bytes[off], bytes[off + 1]]);
    off += 2;
    if version != PACKET_VERSION && version != 2 {
        bail!("unsupported packet version {}", version);
    }

    let suite =
        SuiteId::try_from(bytes[off]).map_err(|_| anyhow::anyhow!("unsupported suite id"))?;
    off += 1;
    off += 1; // reserved

    let name_len = u16::from_le_bytes([bytes[off], bytes[off + 1]]) as usize;
    off += 2;
    if off + name_len > bytes.len() {
        bail!("packet truncated at filename");
    }
    let filename = String::from_utf8(bytes[off..off + name_len].to_vec())
        .context("filename is not valid UTF-8")?;
    off += name_len;

    if off + 16 + CT_BYTES + 8 > bytes.len() {
        bail!("packet truncated before payload");
    }
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&bytes[off..off + 16]);
    off += 16;

    let mut kem_ct = [0u8; CT_BYTES];
    kem_ct.copy_from_slice(&bytes[off..off + CT_BYTES]);
    off += CT_BYTES;

    let sender_pubkey = if version >= 2 {
        if off + 4 > bytes.len() {
            bail!("packet truncated at sender key length");
        }
        let sender_len =
            u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
                as usize;
        off += 4;
        if off + sender_len > bytes.len() {
            bail!("packet truncated at sender key");
        }
        let v = if sender_len > 0 {
            Some(bytes[off..off + sender_len].to_vec())
        } else {
            None
        };
        off += sender_len;
        v
    } else {
        None
    };

    let payload_len = u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ]) as usize;
    off += 8;
    if off + payload_len > bytes.len() {
        bail!("packet truncated at payload");
    }
    let payload_ct = bytes[off..off + payload_len].to_vec();

    Ok(ExchangePacket {
        suite,
        filename,
        file_id,
        kem_ct,
        sender_pubkey,
        payload_ct,
    })
}

fn parse_suite(v: &str) -> Result<SuiteId> {
    match v {
        "xchacha20" => Ok(SuiteId::XChaCha20Poly1305),
        "aesgcm" => Ok(SuiteId::Aes256Gcm),
        _ => bail!("unsupported suite: {v}"),
    }
}

fn to_fixed<const N: usize>(src: &[u8], label: &str) -> Result<[u8; N]> {
    if src.len() != N {
        bail!(
            "{} length mismatch: expected {}, got {}",
            label,
            N,
            src.len()
        );
    }
    let mut out = [0u8; N];
    out.copy_from_slice(src);
    Ok(out)
}

fn sanitize_filename(name: &str) -> String {
    let mut s = name
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect::<String>();
    if s.is_empty() {
        s = "received.bin".to_string();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{format_inspect_legacy, ExchangeInspectData};

    #[test]
    fn inspect_legacy_output_contract() {
        let info = ExchangeInspectData {
            filename: "payload.txt".to_string(),
            suite: "xchacha20".to_string(),
            payload_ct_len: 1234,
            sender_fingerprint: Some("ABCDEF".to_string()),
        };
        let out = format_inspect_legacy(&info);
        assert!(out.contains("filename=payload.txt\n"));
        assert!(out.contains("suite=xchacha20\n"));
        assert!(out.contains("payload_ct_len=1234\n"));
        assert!(out.contains("sender_fingerprint=ABCDEF\n"));
    }

    #[test]
    fn inspect_legacy_output_contract_empty_sender() {
        let info = ExchangeInspectData {
            filename: "payload.txt".to_string(),
            suite: "aesgcm".to_string(),
            payload_ct_len: 10,
            sender_fingerprint: None,
        };
        let out = format_inspect_legacy(&info);
        assert!(out.contains("sender_fingerprint=\n"));
    }
}
