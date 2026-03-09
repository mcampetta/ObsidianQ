use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand};
use obsidianq_core::crypto::kem::{self, DK_BYTES, EK_BYTES};

use crate::public_identity::{
    compute_fingerprint_b64, render_identity_block, PublicIdentity, ID_ALGORITHM,
};

use super::{read_pub, write_priv, write_pub};

#[derive(Args)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub cmd: KeyCmd,
}

#[derive(Subcommand)]
pub enum KeyCmd {
    /// Generate a fresh ML-KEM-768 keypair (optionally with identity metadata)
    Generate(KeyGenerateArgs),
    /// Export a public identity document to stdout or file
    ExportPublic(ExportPublicArgs),
}

#[derive(Args)]
pub struct KeyGenerateArgs {
    /// Output path for the public key (.bin raw by default, .pem for wrapped Base64)
    #[arg(long, default_value = "obsidianq_pub.bin")]
    pub pubkey: PathBuf,
    /// Output path for the private key (.bin raw by default, .pem for wrapped Base64)
    #[arg(long, default_value = "obsidianq_priv.bin")]
    pub privkey: PathBuf,
    /// Optional identity display name
    #[arg(long)]
    pub name: Option<String>,
    /// Optional identity email
    #[arg(long)]
    pub email: Option<String>,
    /// Optional device label
    #[arg(long)]
    pub device: Option<String>,
}

#[derive(Args)]
pub struct ExportPublicArgs {
    /// Public key path (.bin/.pem). If omitted, defaults are probed.
    #[arg(long)]
    pub pubkey: Option<PathBuf>,
    /// Output .obsqpub file path. If omitted, identity is printed to stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: KeyArgs) -> Result<()> {
    match args.cmd {
        KeyCmd::Generate(a) => run_generate(a),
        KeyCmd::ExportPublic(a) => run_export_public(a),
    }
}

pub fn run_generate(a: KeyGenerateArgs) -> Result<()> {
    let (ek, dk) = kem::generate_keypair();
    write_pub(&a.pubkey, ek.0.as_ref())?;
    write_priv(&a.privkey, dk.0.as_ref())?;
    println!("Public key  -> {}", a.pubkey.display());
    println!("Private key -> {}", a.privkey.display());
    println!("Key sizes: EK={} B, DK={} B", EK_BYTES, DK_BYTES);

    if a.name.is_some() || a.email.is_some() || a.device.is_some() {
        let fp = compute_fingerprint_b64(ek.0.as_ref());
        let created = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut map = load_meta_records()?;
        map.insert(
            fp.clone(),
            MetaRecord {
                name: clean(a.name),
                email: clean(a.email),
                device: clean(a.device),
                created: Some(created),
                algorithm: ID_ALGORITHM.to_string(),
            },
        );
        save_meta_records(&map)?;
        println!("Stored identity metadata for fingerprint {}", fp);
    }
    Ok(())
}

fn run_export_public(a: ExportPublicArgs) -> Result<()> {
    let pubkey_path = if let Some(p) = a.pubkey {
        p
    } else {
        find_default_public_key().context("no default public key found; use --pubkey <path>")?
    };
    let raw = read_pub(&pubkey_path)
        .with_context(|| format!("read public key {}", pubkey_path.display()))?;
    if raw.is_empty() {
        bail!("public key is empty");
    }
    let fp = compute_fingerprint_b64(&raw);

    let map = load_meta_records()?;
    let rec = map.get(&fp);
    let identity = PublicIdentity {
        version: 1,
        name: rec.and_then(|r| r.name.clone()),
        email: rec.and_then(|r| r.email.clone()),
        device: rec.and_then(|r| r.device.clone()),
        created: rec.and_then(|r| r.created.clone()),
        algorithm: rec
            .map(|r| r.algorithm.clone())
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| ID_ALGORITHM.to_string()),
        fingerprint: fp,
        public_key_bytes: raw,
    };
    let doc = render_identity_block(&identity);

    if let Some(out) = a.output {
        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create output dir {}", parent.display()))?;
            }
        }
        std::fs::write(&out, doc).with_context(|| format!("write {}", out.display()))?;
        println!("Wrote public identity: {}", out.display());
    } else {
        print!("{doc}");
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct MetaRecord {
    name: Option<String>,
    email: Option<String>,
    device: Option<String>,
    created: Option<String>,
    algorithm: String,
}

fn load_meta_records() -> Result<BTreeMap<String, MetaRecord>> {
    let path = meta_path();
    if !path.exists() {
        return Ok(BTreeMap::new());
    }

    let mut out = BTreeMap::new();
    for line in std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?
        .lines()
    {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 6 {
            continue;
        }
        out.insert(
            parts[0].trim().to_string(),
            MetaRecord {
                name: clean(non_empty(parts[1])),
                email: clean(non_empty(parts[2])),
                device: clean(non_empty(parts[3])),
                created: clean(non_empty(parts[4])),
                algorithm: parts[5].trim().to_string(),
            },
        );
    }
    Ok(out)
}

fn save_meta_records(map: &BTreeMap<String, MetaRecord>) -> Result<()> {
    let path = meta_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create metadata dir {}", parent.display()))?;
    }

    let mut buf = String::new();
    for (fp, rec) in map {
        buf.push_str(fp);
        buf.push('\t');
        buf.push_str(rec.name.as_deref().unwrap_or(""));
        buf.push('\t');
        buf.push_str(rec.email.as_deref().unwrap_or(""));
        buf.push('\t');
        buf.push_str(rec.device.as_deref().unwrap_or(""));
        buf.push('\t');
        buf.push_str(rec.created.as_deref().unwrap_or(""));
        buf.push('\t');
        buf.push_str(rec.algorithm.trim());
        buf.push('\n');
    }
    std::fs::write(&path, buf).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn meta_path() -> PathBuf {
    app_data_dir().join("public_identity_meta_v1.tsv")
}

fn app_data_dir() -> PathBuf {
    if let Ok(v) = std::env::var("LOCALAPPDATA") {
        if !v.trim().is_empty() {
            return PathBuf::from(v).join("ObsidianQ");
        }
    }
    if let Ok(v) = std::env::var("APPDATA") {
        if !v.trim().is_empty() {
            return PathBuf::from(v).join("ObsidianQ");
        }
    }
    if let Ok(v) = std::env::var("HOME") {
        if !v.trim().is_empty() {
            return PathBuf::from(v).join(".obsidianq");
        }
    }
    PathBuf::from(".")
}

fn find_default_public_key() -> Option<PathBuf> {
    let local = app_data_dir().join("keys");
    let candidates = [
        local.join("obsidianq_pub.bin"),
        local.join("obsidianq_pub.pem"),
        PathBuf::from("obsidianq_pub.bin"),
        PathBuf::from("obsidianq_pub.pem"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn non_empty(v: &str) -> Option<String> {
    let t = v.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn clean(v: Option<String>) -> Option<String> {
    v.and_then(|s| {
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}
