use anyhow::{bail, Context, Result};
use base64ct::{Base64, Encoding};

pub const ID_BEGIN: &str = "-----BEGIN OBSIDIANQ PUBLIC IDENTITY-----";
pub const ID_END: &str = "-----END OBSIDIANQ PUBLIC IDENTITY-----";
const PUB_HEADER: &str = "-----BEGIN OBSIDIANQ PUBLIC KEY-----";
const PUB_FOOTER: &str = "-----END OBSIDIANQ PUBLIC KEY-----";
pub const ID_ALGORITHM: &str = "Kyber768-R3+X25519";

#[derive(Debug, Clone)]
pub struct PublicIdentity {
    pub version: u8,
    pub name: Option<String>,
    pub email: Option<String>,
    pub device: Option<String>,
    pub created: Option<String>,
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key_bytes: Vec<u8>,
    pub classical_public_key_bytes: Option<Vec<u8>>,
}

pub fn contains_identity_block(text: &str) -> bool {
    text.contains(ID_BEGIN)
}

pub fn compute_fingerprint_b64(key_bytes: &[u8]) -> String {
    let hash = blake3::hash(key_bytes);
    Base64::encode_string(hash.as_bytes())
}

pub fn parse_identity_block(text: &str) -> Result<PublicIdentity> {
    enum Section {
        Fields,
        Key,
        ClassicalKey,
    }

    let begin = text.find(ID_BEGIN).context("identity header not found")?;
    let end = text.find(ID_END).context("identity footer not found")?;
    if end <= begin {
        bail!("identity footer appears before header");
    }

    let body = &text[begin + ID_BEGIN.len()..end];
    let mut version: Option<u8> = None;
    let mut name: Option<String> = None;
    let mut email: Option<String> = None;
    let mut device: Option<String> = None;
    let mut created: Option<String> = None;
    let mut algorithm: Option<String> = None;
    let mut fingerprint: Option<String> = None;
    let mut section = Section::Fields;
    let mut classical_key_lines: Vec<String> = Vec::new();
    let mut key_lines: Vec<String> = Vec::new();

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("key:") {
            section = Section::Key;
            continue;
        }
        if line.eq_ignore_ascii_case("classical_key:") {
            section = Section::ClassicalKey;
            continue;
        }
        match section {
            Section::Key => {
                key_lines.push(line.to_string());
                continue;
            }
            Section::ClassicalKey => {
                classical_key_lines.push(line.to_string());
                continue;
            }
            Section::Fields => {}
        }
        let Some((k, v)) = line.split_once(':') else {
            bail!("invalid identity line: {line}");
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match key.as_str() {
            "version" => {
                version = Some(val.parse::<u8>().context("invalid identity version")?);
            }
            "name" => name = non_empty(val),
            "email" => email = non_empty(val),
            "device" => device = non_empty(val),
            "created" => created = non_empty(val),
            "algorithm" => algorithm = non_empty(val),
            "fingerprint" => fingerprint = non_empty(val),
            _ => {}
        }
    }

    let version = version.context("missing required field: version")?;
    let algorithm = algorithm.context("missing required field: algorithm")?;
    let fingerprint = fingerprint.context("missing required field: fingerprint")?;
    if key_lines.is_empty() {
        bail!("missing required field: key");
    }

    let key_b64: String = key_lines.into_iter().collect();
    let public_key_bytes =
        Base64::decode_vec(&key_b64).map_err(|e| anyhow::anyhow!("invalid key base64: {e}"))?;
    if public_key_bytes.is_empty() {
        bail!("public key cannot be empty");
    }

    let computed = compute_fingerprint_b64(&public_key_bytes);
    if normalize_fp(&computed) != normalize_fp(&fingerprint) {
        bail!("identity fingerprint does not match key bytes");
    }

    Ok(PublicIdentity {
        version,
        name,
        email,
        device,
        created,
        algorithm,
        fingerprint: computed,
        public_key_bytes,
        classical_public_key_bytes: if classical_key_lines.is_empty() {
            None
        } else {
            Some(
                Base64::decode_vec(&classical_key_lines.into_iter().collect::<String>())
                    .map_err(|e| anyhow::anyhow!("invalid classical key base64: {e}"))?,
            )
        },
    })
}

pub fn decode_public_key_text_or_pem(text: &str) -> Result<Vec<u8>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("empty key input");
    }

    if trimmed.contains(PUB_HEADER) {
        let start = trimmed
            .find(PUB_HEADER)
            .map(|i| i + PUB_HEADER.len())
            .context("public key PEM header not found")?;
        let end = trimmed[start..]
            .find(PUB_FOOTER)
            .map(|i| start + i)
            .context("public key PEM footer not found")?;
        let b64: String = trimmed[start..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let decoded =
            Base64::decode_vec(&b64).map_err(|e| anyhow::anyhow!("base64 decode: {e}"))?;
        if decoded.is_empty() {
            bail!("decoded public key is empty");
        }
        return Ok(decoded);
    }

    let b64: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = Base64::decode_vec(&b64).map_err(|e| anyhow::anyhow!("base64 decode: {e}"))?;
    if decoded.is_empty() {
        bail!("decoded public key is empty");
    }
    Ok(decoded)
}

pub fn render_identity_block(identity: &PublicIdentity) -> String {
    let mut out = String::new();
    out.push_str(ID_BEGIN);
    out.push('\n');
    out.push_str(&format!("version:{}\n", identity.version));
    if let Some(v) = identity.name.as_deref().filter(|v| !v.trim().is_empty()) {
        out.push_str("name:");
        out.push_str(v.trim());
        out.push('\n');
    }
    if let Some(v) = identity.email.as_deref().filter(|v| !v.trim().is_empty()) {
        out.push_str("email:");
        out.push_str(v.trim());
        out.push('\n');
    }
    if let Some(v) = identity.device.as_deref().filter(|v| !v.trim().is_empty()) {
        out.push_str("device:");
        out.push_str(v.trim());
        out.push('\n');
    }
    if let Some(v) = identity.created.as_deref().filter(|v| !v.trim().is_empty()) {
        out.push_str("created:");
        out.push_str(v.trim());
        out.push('\n');
    }
    out.push_str("algorithm:");
    out.push_str(identity.algorithm.trim());
    out.push('\n');
    out.push_str("fingerprint:");
    out.push_str(identity.fingerprint.trim());
    out.push('\n');
    out.push('\n');
    out.push_str("key:\n");
    out.push_str(&chunk_base64_lines(&identity.public_key_bytes, 64));
    out.push('\n');
    if let Some(classical) = identity
        .classical_public_key_bytes
        .as_deref()
        .filter(|v| !v.is_empty())
    {
        out.push('\n');
        out.push_str("classical_key:\n");
        out.push_str(&chunk_base64_lines(classical, 64));
        out.push('\n');
    }
    out.push_str(ID_END);
    out.push('\n');
    out
}

fn non_empty(v: &str) -> Option<String> {
    let t = v.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn normalize_fp(v: &str) -> String {
    v.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

fn chunk_base64_lines(raw: &[u8], line_len: usize) -> String {
    let b64 = Base64::encode_string(raw);
    if line_len == 0 || b64.len() <= line_len {
        return b64;
    }
    let mut out = String::with_capacity(b64.len() + (b64.len() / line_len) + 8);
    let mut i = 0usize;
    while i < b64.len() {
        let end = std::cmp::min(i + line_len, b64.len());
        out.push_str(&b64[i..end]);
        if end < b64.len() {
            out.push('\n');
        }
        i = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trip_preserves_classical_key() {
        let identity = PublicIdentity {
            version: 1,
            name: Some("Alice".to_string()),
            email: None,
            device: Some("Workstation".to_string()),
            created: Some("2026-03-22T00:00:00Z".to_string()),
            algorithm: ID_ALGORITHM.to_string(),
            fingerprint: compute_fingerprint_b64(&[1u8; 16]),
            public_key_bytes: vec![1u8; 16],
            classical_public_key_bytes: Some(vec![2u8; 32]),
        };

        let rendered = render_identity_block(&identity);
        let parsed = parse_identity_block(&rendered).expect("parse identity");
        assert_eq!(parsed.algorithm, ID_ALGORITHM);
        assert_eq!(parsed.public_key_bytes, vec![1u8; 16]);
        assert_eq!(parsed.classical_public_key_bytes, Some(vec![2u8; 32]));
    }
}
