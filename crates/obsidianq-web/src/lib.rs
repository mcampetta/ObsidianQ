use std::io::{Cursor, Read};

use anyhow::{bail, Context, Result};
use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use zip::ZipArchive;

use obsidianq_core::crypto::kdf::{self, Argon2Params};
use obsidianq_core::delivery::{
    DeliveryArtifactsManifest, DeliveryFileEntry, DeliveryOptionsManifest, PackageFormat,
    PayloadManifest, RecipientMode, SecureDeliveryManifest, SenderIdentityManifest,
    MANIFEST_FILE_NAME, PAYLOAD_FILE_NAME,
};
use obsidianq_core::format::{flags, FileHeader, Mode, SuiteId};

const SFX_MAGIC: &[u8; 8] = b"OBSQSFX1";
const SFX_TRAILER_LEN: usize = 24;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationView {
    package_signature_valid: bool,
    signing_identity_present: bool,
    contents_match_manifest: bool,
    no_tampering_detected: bool,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InspectionView {
    kind: String,
    container_type: String,
    schema_version: u8,
    package_id: Option<String>,
    created_utc: String,
    obsidianq_version: Option<String>,
    package_name: String,
    recipient_mode: Option<String>,
    package_format: String,
    source_item_count: usize,
    source_total_bytes: u64,
    has_instructions: bool,
    payload_sha256: String,
    signed: bool,
    signing_identity: Option<String>,
    signing_fingerprint: Option<String>,
    signing_email: Option<String>,
    signing_device: Option<String>,
    signature_algorithm: Option<String>,
    files: Vec<DeliveryFileEntry>,
    verification: VerificationView,
}

#[derive(Debug, Clone)]
struct SignatureVerifyInfo {
    signed: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct CanonicalSignedManifestV1<'a> {
    schema_version: u8,
    package_format: &'a PackageFormat,
    created_utc: &'a str,
    package_name: &'a str,
    payload: &'a PayloadManifest,
    options: &'a DeliveryOptionsManifest,
    artifacts: &'a DeliveryArtifactsManifest,
    sender: &'a SenderIdentityManifest,
}

#[derive(Serialize)]
struct CanonicalSignedManifestV2<'a> {
    schema_version: u8,
    package_format: &'a PackageFormat,
    created_utc: &'a str,
    package_name: &'a str,
    payload: &'a PayloadManifest,
    options: &'a DeliveryOptionsManifest,
    artifacts: &'a DeliveryArtifactsManifest,
    files: &'a [DeliveryFileEntry],
}

#[derive(Serialize)]
struct CanonicalSignedManifestV3<'a> {
    schema_version: u8,
    package_uuid: &'a Option<String>,
    package_format: &'a PackageFormat,
    created_utc: &'a str,
    obsidianq_version: &'a Option<String>,
    package_name: &'a str,
    recipient_mode: &'a Option<RecipientMode>,
    payload: &'a PayloadManifest,
    options: &'a DeliveryOptionsManifest,
    artifacts: &'a DeliveryArtifactsManifest,
    files: &'a [DeliveryFileEntry],
}

#[wasm_bindgen]
pub fn inspect_secure_delivery(bytes: &[u8]) -> Result<JsValue, JsValue> {
    if looks_like_obsq(bytes) {
        let inspection = inspect_obsq_bytes(bytes).map_err(js_err)?;
        return serde_wasm_bindgen::to_value(&inspection).map_err(js_err);
    }
    let (package_bytes, container_type) = extract_package_bytes(bytes)?;
    let inspection = inspect_package_bytes(package_bytes, container_type).map_err(js_err)?;
    serde_wasm_bindgen::to_value(&inspection).map_err(js_err)
}

#[wasm_bindgen]
pub fn decrypt_secure_delivery_to_bundle(bytes: &[u8], password: &str) -> Result<Vec<u8>, JsValue> {
    if password.is_empty() {
        return Err(js_err("Password is required."));
    }
    if looks_like_obsq(bytes) {
        return decrypt_payload_bytes(bytes, password.as_bytes()).map_err(map_decrypt_err);
    }
    let (package_bytes, _) = extract_package_bytes(bytes)?;
    let payload = read_zip_entry_bytes(package_bytes, PAYLOAD_FILE_NAME).map_err(js_err)?;
    decrypt_payload_bytes(&payload, password.as_bytes()).map_err(map_decrypt_err)
}

fn looks_like_obsq(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == b"OBSQ"
}

fn extract_package_bytes<'a>(bytes: &'a [u8]) -> Result<(&'a [u8], &'static str), JsValue> {
    if bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04" {
        if read_zip_entry_bytes(bytes, MANIFEST_FILE_NAME).is_ok() {
            return Ok((bytes, "Secure Delivery ZIP"));
        }
        if let Ok(exe_bytes) = extract_sfx_from_wrapper_zip(bytes) {
            return extract_package_bytes(exe_bytes);
        }
        return Err(js_err(
            "this ZIP is not a Secure Delivery package. Expected secure_delivery_manifest.json or a wrapped self-extracting package.",
        ));
    }
    if bytes.len() >= SFX_TRAILER_LEN && &bytes[bytes.len() - 8..] == SFX_MAGIC {
        let pkg_len = u64::from_le_bytes(
            bytes[bytes.len() - SFX_TRAILER_LEN..bytes.len() - 16]
                .try_into()
                .unwrap(),
        ) as usize;
        let cli_len =
            u64::from_le_bytes(bytes[bytes.len() - 16..bytes.len() - 8].try_into().unwrap())
                as usize;
        let package_offset = bytes
            .len()
            .checked_sub(SFX_TRAILER_LEN + pkg_len + cli_len)
            .context("malformed self-extracting package trailer")
            .map_err(js_err)?;
        let package_end = package_offset + pkg_len;
        if package_end > bytes.len() {
            return Err(js_err("malformed self-extracting package layout"));
        }
        return Ok((
            &bytes[package_offset..package_end],
            "Self-Extracting Package (EXE)",
        ));
    }
    Err(js_err(
        "unsupported file type. Drop a Secure Delivery ZIP or self-extracting EXE package.",
    ))
}

fn extract_sfx_from_wrapper_zip(package_bytes: &[u8]) -> Result<&[u8]> {
    let reader = Cursor::new(package_bytes);
    let mut zip = ZipArchive::new(reader).context("read wrapper zip")?;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .with_context(|| format!("read wrapper zip entry {i}"))?;
        let name = entry.name().to_ascii_lowercase();
        if !name.ends_with(".exe") {
            continue;
        }
        let mut exe = Vec::new();
        entry
            .read_to_end(&mut exe)
            .with_context(|| format!("read wrapper zip entry {name}"))?;
        if exe.len() >= SFX_TRAILER_LEN && &exe[exe.len() - 8..] == SFX_MAGIC {
            let leaked: &'static [u8] = Box::leak(exe.into_boxed_slice());
            return Ok(leaked);
        }
    }
    bail!("wrapper zip does not contain a self-extracting package executable");
}

fn inspect_package_bytes(package_bytes: &[u8], container_type: &str) -> Result<InspectionView> {
    let manifest = read_manifest_from_package_bytes(package_bytes)?;
    if !matches!(manifest.schema_version, 1 | 2 | 3 | 4) {
        bail!(
            "unsupported secure delivery schema version: {}",
            manifest.schema_version
        );
    }

    let signature_info = verify_manifest_signature_for_package_bytes(package_bytes, &manifest)?;
    let sender = load_sender_identity_for_package_bytes(package_bytes, &manifest)?;
    let payload_verification = verify_payload_hash(package_bytes, &manifest);

    Ok(InspectionView {
        kind: "secure_delivery".to_string(),
        container_type: container_type.to_string(),
        schema_version: manifest.schema_version,
        package_id: manifest.package_uuid.clone(),
        created_utc: manifest.created_utc.clone(),
        obsidianq_version: manifest.obsidianq_version.clone(),
        package_name: manifest.package_name.clone(),
        recipient_mode: manifest.recipient_mode.as_ref().map(|m| format!("{m:?}")),
        package_format: format!("{:?}", manifest.package_format),
        source_item_count: manifest.payload.source_item_count,
        source_total_bytes: manifest.payload.source_total_bytes,
        has_instructions: manifest.options.has_instructions,
        payload_sha256: manifest.payload.integrity.hex.clone(),
        signed: signature_info.signed,
        signing_identity: sender
            .as_ref()
            .and_then(|s| s.name.as_deref().map(strip_bom).map(ToOwned::to_owned)),
        signing_fingerprint: sender.as_ref().map(|s| s.fingerprint.clone()),
        signing_email: sender
            .as_ref()
            .and_then(|s| s.email.as_deref().map(strip_bom).map(ToOwned::to_owned)),
        signing_device: sender
            .as_ref()
            .and_then(|s| s.device.as_deref().map(strip_bom).map(ToOwned::to_owned)),
        signature_algorithm: manifest.signature.as_ref().map(|s| s.algorithm.clone()),
        files: manifest.files.clone(),
        verification: VerificationView {
            package_signature_valid: signature_info.signed,
            signing_identity_present: sender.is_some(),
            contents_match_manifest: payload_verification.is_ok(),
            no_tampering_detected: payload_verification.is_ok() && signature_info.error.is_none(),
            error: payload_verification
                .err()
                .map(|e| e.to_string())
                .or(signature_info.error.clone()),
        },
    })
}

fn inspect_obsq_bytes(bytes: &[u8]) -> Result<InspectionView> {
    let mut cursor = Cursor::new(bytes);
    let header = FileHeader::read_from(&mut cursor).context("parse file header")?;
    Ok(InspectionView {
        kind: "obsq".to_string(),
        container_type: "Encrypted File (.obsq)".to_string(),
        schema_version: header.version,
        package_id: None,
        created_utc: "-".to_string(),
        obsidianq_version: None,
        package_name: "Encrypted file".to_string(),
        recipient_mode: Some(match header.mode {
            Mode::Password => "Password".to_string(),
            Mode::Pqc => "Legacy Contact".to_string(),
        }),
        package_format: match header.suite {
            SuiteId::XChaCha20Poly1305 => "XChaCha20-Poly1305".to_string(),
            SuiteId::Aes256Gcm => "AES-256-GCM".to_string(),
        },
        source_item_count: 1,
        source_total_bytes: bytes.len() as u64,
        has_instructions: false,
        payload_sha256: sha256_bytes_hex(bytes),
        signed: false,
        signing_identity: None,
        signing_fingerprint: None,
        signing_email: None,
        signing_device: None,
        signature_algorithm: None,
        files: Vec::new(),
        verification: VerificationView {
            package_signature_valid: false,
            signing_identity_present: false,
            contents_match_manifest: true,
            no_tampering_detected: true,
            error: if header.flags & flags::COMPRESSED != 0 {
                Some("Compressed .obsq files are not yet supported in Web Decrypt.".to_string())
            } else if matches!(header.mode, Mode::Pqc) {
                Some("Legacy recipient .obsq files are not yet supported in Web Decrypt.".to_string())
            } else {
                None
            },
        },
    })
}

fn read_manifest_from_package_bytes(package_bytes: &[u8]) -> Result<SecureDeliveryManifest> {
    let data = read_zip_entry_bytes(package_bytes, MANIFEST_FILE_NAME)?;
    serde_json::from_slice(&data).context("parse manifest json")
}

fn read_zip_entry_bytes(package_bytes: &[u8], entry_name: &str) -> Result<Vec<u8>> {
    let reader = Cursor::new(package_bytes);
    let mut zip = ZipArchive::new(reader).context("read package zip")?;
    let mut entry = zip
        .by_name(entry_name)
        .with_context(|| format!("{entry_name} missing from package"))?;
    let mut data = Vec::new();
    entry
        .read_to_end(&mut data)
        .with_context(|| format!("read {entry_name}"))?;
    Ok(data)
}

fn verify_payload_hash(package_bytes: &[u8], manifest: &SecureDeliveryManifest) -> Result<()> {
    let payload = read_zip_entry_bytes(package_bytes, PAYLOAD_FILE_NAME)?;
    let actual = sha256_bytes_hex(&payload);
    let expected = manifest.payload.integrity.hex.to_ascii_lowercase();
    if actual != expected {
        bail!("payload hash mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn verify_manifest_signature_for_package_bytes(
    package_bytes: &[u8],
    manifest: &SecureDeliveryManifest,
) -> Result<SignatureVerifyInfo> {
    let Some(signature) = &manifest.signature else {
        return Ok(SignatureVerifyInfo {
            signed: false,
            error: None,
        });
    };

    if !signature.algorithm.eq_ignore_ascii_case("ed25519") {
        bail!(
            "unsupported package signature algorithm: {}",
            signature.algorithm
        );
    }
    if !matches!(
        signature.signed_fields.trim(),
        "manifest-v1" | "manifest-v2" | "manifest-v3"
    ) {
        bail!(
            "unsupported signed_fields value: {}",
            signature.signed_fields
        );
    }

    let sender = load_sender_identity_for_package_bytes(package_bytes, manifest)?
        .context("sender identity missing from signed package")?;
    let public_key = Base64::decode_vec(&sender.public_key_b64)
        .map_err(|e| anyhow::anyhow!("invalid sender public key base64: {e}"))?;
    if public_key.len() != 32 {
        bail!(
            "invalid sender public key length: expected 32, got {}",
            public_key.len()
        );
    }
    let verify_key = VerifyingKey::from_bytes(
        &public_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid sender public key bytes"))?,
    )
    .map_err(|e| anyhow::anyhow!("parse sender public key: {e}"))?;
    let sig_bytes = Base64::decode_vec(&signature.signature_b64)
        .map_err(|e| anyhow::anyhow!("invalid signature base64: {e}"))?;
    if sig_bytes.len() != 64 {
        bail!(
            "invalid manifest signature length: expected 64, got {}",
            sig_bytes.len()
        );
    }
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| anyhow::anyhow!("parse signature: {e}"))?;
    let msg = canonical_manifest_bytes(manifest, &signature.signed_fields)?;
    if let Some(hash) = &signature.manifest_hash {
        if !hash.algorithm.eq_ignore_ascii_case("sha256") {
            bail!("unsupported manifest hash algorithm: {}", hash.algorithm);
        }
        let actual_hash = sha256_bytes_hex(&msg);
        if !actual_hash.eq_ignore_ascii_case(&hash.hex) {
            bail!(
                "manifest hash mismatch: expected {}, got {}",
                hash.hex,
                actual_hash
            );
        }
    }
    verify_key
        .verify(&msg, &sig)
        .map_err(|e| anyhow::anyhow!("manifest signature verification failed: {e}"))?;

    Ok(SignatureVerifyInfo {
        signed: true,
        error: None,
    })
}

fn canonical_manifest_bytes(
    manifest: &SecureDeliveryManifest,
    signed_fields: &str,
) -> Result<Vec<u8>> {
    match signed_fields.trim() {
        "manifest-v1" => {
            let sender = manifest
                .sender
                .as_ref()
                .context("sender identity missing")?;
            let canonical = CanonicalSignedManifestV1 {
                schema_version: manifest.schema_version,
                package_format: &manifest.package_format,
                created_utc: &manifest.created_utc,
                package_name: &manifest.package_name,
                payload: &manifest.payload,
                options: &manifest.options,
                artifacts: &manifest.artifacts,
                sender,
            };
            serde_json::to_vec(&canonical).context("serialize canonical manifest")
        }
        "manifest-v2" => {
            let canonical = CanonicalSignedManifestV2 {
                schema_version: manifest.schema_version,
                package_format: &manifest.package_format,
                created_utc: &manifest.created_utc,
                package_name: &manifest.package_name,
                payload: &manifest.payload,
                options: &manifest.options,
                artifacts: &manifest.artifacts,
                files: &manifest.files,
            };
            serde_json::to_vec(&canonical).context("serialize canonical manifest")
        }
        "manifest-v3" => {
            let canonical = CanonicalSignedManifestV3 {
                schema_version: manifest.schema_version,
                package_uuid: &manifest.package_uuid,
                package_format: &manifest.package_format,
                created_utc: &manifest.created_utc,
                obsidianq_version: &manifest.obsidianq_version,
                package_name: &manifest.package_name,
                recipient_mode: &manifest.recipient_mode,
                payload: &manifest.payload,
                options: &manifest.options,
                artifacts: &manifest.artifacts,
                files: &manifest.files,
            };
            serde_json::to_vec(&canonical).context("serialize canonical manifest")
        }
        _ => bail!("unsupported signed_fields value: {signed_fields}"),
    }
}

fn load_sender_identity_for_package_bytes(
    package_bytes: &[u8],
    manifest: &SecureDeliveryManifest,
) -> Result<Option<SenderIdentityManifest>> {
    if let Some(sender) = manifest.sender.clone() {
        return Ok(Some(sender));
    }
    let Some(identity_file) = manifest.artifacts.sender_identity_file.as_deref() else {
        return Ok(None);
    };
    let data = read_zip_entry_bytes(package_bytes, identity_file)?;
    if let Some(expected) = manifest.artifacts.sender_identity_sha256.as_deref() {
        let actual = sha256_bytes_hex(&data);
        if !actual.eq_ignore_ascii_case(expected) {
            bail!("sender identity hash mismatch: expected {expected}, got {actual}");
        }
    }
    let sender: SenderIdentityManifest =
        serde_json::from_slice(&data).context("parse sender identity json")?;
    Ok(Some(sender))
}

fn decrypt_payload_bytes(payload: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(payload);
    let header = FileHeader::read_from(&mut cursor).context("parse payload header")?;
    if !matches!(header.mode, Mode::Password) {
        bail!("Web Decrypt currently supports password-mode payloads only");
    }
    if header.kem_data.len() != 32 {
        bail!(
            "malformed payload header: expected 32-byte salt, got {}",
            header.kem_data.len()
        );
    }

    let mut salt = [0u8; 32];
    salt.copy_from_slice(&header.kem_data);
    let master_key = kdf::derive_password_key(password, &salt, &Argon2Params::default())
        .context("derive password key")?;

    let mut reader = Cursor::new(payload);
    let mut plain = Vec::new();
    obsidianq_core::decrypt(&master_key, &mut reader, &mut plain).context("decrypt payload")?;
    Ok(plain)
}

fn sha256_bytes_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn js_err<E: std::fmt::Display>(err: E) -> JsValue {
    JsValue::from_str(&err.to_string())
}

fn strip_bom(input: &str) -> &str {
    input.trim_start_matches('\u{feff}')
}

fn map_decrypt_err<E: std::fmt::Display>(err: E) -> JsValue {
    let text = err.to_string();
    if text.contains("HeaderMacFailure")
        || text.contains("ChunkAuthFailure")
        || text.contains("FooterMacFailure")
        || text.contains("AEAD")
        || text.contains("decrypt payload")
    {
        return JsValue::from_str("Incorrect password or unsupported encrypted file.");
    }
    if text.contains("Web Decrypt currently supports password-mode payloads only") {
        return JsValue::from_str(
            "This file uses a mode that is not yet supported in Web Decrypt.",
        );
    }
    if text.contains("compressed payloads are not supported in wasm builds")
        || text.contains("Compressed .obsq files are not yet supported")
    {
        return JsValue::from_str("Compressed files are not yet supported in Web Decrypt.");
    }
    JsValue::from_str(&text)
}
