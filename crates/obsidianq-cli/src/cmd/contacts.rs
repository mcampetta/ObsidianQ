use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use base64ct::{Base64, Encoding};
use chrono::Local;
use clap::{Args, Subcommand};

use crate::public_identity::{
    compute_fingerprint_b64, contains_identity_block, decode_public_key_text_or_pem,
    parse_identity_block,
};

use super::read_pub;

#[derive(Args)]
pub struct ContactsArgs {
    #[command(subcommand)]
    pub cmd: ContactsCmd,
}

#[derive(Subcommand)]
pub enum ContactsCmd {
    /// Import an .obsqpub identity document or raw public key file
    Import(ImportArgs),
}

#[derive(Args)]
pub struct ImportArgs {
    /// Path to .obsqpub, PEM, raw base64 text, or raw key bytes.
    pub input: PathBuf,
    /// Contact name override. Required for raw key import without identity metadata.
    #[arg(long)]
    pub name: Option<String>,
}

pub fn run(args: ContactsArgs) -> Result<()> {
    match args.cmd {
        ContactsCmd::Import(a) => run_import(a),
    }
}

fn run_import(args: ImportArgs) -> Result<()> {
    let bytes =
        std::fs::read(&args.input).with_context(|| format!("read {}", args.input.display()))?;
    if bytes.is_empty() {
        bail!("input file is empty");
    }

    let (name_hint, key_bytes, fingerprint) = if let Ok(text) = std::str::from_utf8(&bytes) {
        if contains_identity_block(text) {
            let identity = parse_identity_block(text).context("parse public identity")?;
            (
                identity.name,
                identity.public_key_bytes.clone(),
                identity.fingerprint.clone(),
            )
        } else {
            let decoded = decode_public_key_text_or_pem(text)
                .or_else(|_| read_pub(&args.input))
                .with_context(|| format!("decode key from {}", args.input.display()))?;
            let fp = compute_fingerprint_b64(&decoded);
            (None, decoded, fp)
        }
    } else {
        let fp = compute_fingerprint_b64(&bytes);
        (None, bytes.clone(), fp)
    };

    let final_name = args
        .name
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| name_hint.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .ok_or_else(|| anyhow::anyhow!("raw key import requires --name <contact-name>"))?;

    let key_b64 = Base64::encode_string(&key_bytes);
    upsert_contact(&final_name, &fingerprint, "PQC", &key_b64)?;
    println!("Imported contact '{}' ({})", final_name, fingerprint);
    Ok(())
}

fn upsert_contact(name: &str, fingerprint: &str, key_type: &str, key_b64: &str) -> Result<()> {
    let path = contacts_tsv_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create contacts dir {}", parent.display()))?;
    }

    let mut rows: Vec<(String, String, String, String, String)> = Vec::new();
    if path.exists() {
        for line in std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?
            .lines()
        {
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 5 {
                continue;
            }
            rows.push((
                parts[0].trim().to_string(),
                parts[1].trim().to_string(),
                parts[2].trim().to_string(),
                parts[3].trim().to_string(),
                parts[4].trim().to_string(),
            ));
        }
    }

    let today = Local::now().format("%m-%d-%Y").to_string();
    let mut updated = false;
    for row in &mut rows {
        if row.1.eq_ignore_ascii_case(fingerprint) {
            row.0 = name.trim().to_string();
            row.2 = key_type.trim().to_string();
            row.3 = today.clone();
            row.4 = key_b64.trim().to_string();
            updated = true;
            break;
        }
    }
    if !updated {
        rows.push((
            name.trim().to_string(),
            fingerprint.trim().to_string(),
            key_type.trim().to_string(),
            today,
            key_b64.trim().to_string(),
        ));
    }

    let mut out = String::new();
    for (n, fp, kt, d, kb64) in rows {
        out.push_str(&n.replace('\t', " "));
        out.push('\t');
        out.push_str(fp.trim());
        out.push('\t');
        out.push_str(kt.trim());
        out.push('\t');
        out.push_str(d.trim());
        out.push('\t');
        out.push_str(kb64.trim());
        out.push('\n');
    }
    std::fs::write(&path, out).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn contacts_tsv_path() -> PathBuf {
    app_data_dir().join("trusted_recipients_v1.tsv")
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
