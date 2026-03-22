use serde::{Deserialize, Serialize};

pub const MANIFEST_FILE_NAME: &str = "secure_delivery_manifest.json";
pub const PAYLOAD_FILE_NAME: &str = "payload.obsq";
pub const INSTRUCTIONS_FILE_NAME: &str = "instructions.txt";
pub const SENDER_IDENTITY_FILE_NAME: &str = "sender_identity.json";
pub const PACKAGE_SUFFIX: &str = "_SecureDelivery";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageFormat {
    SecureDeliveryZip,
    SecureDeliveryExe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientMode {
    Password,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityInfo {
    pub algorithm: String,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadManifest {
    pub file: String,
    pub cipher_suite: String,
    pub integrity: IntegrityInfo,
    pub source_item_count: usize,
    pub source_total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryOptionsManifest {
    pub compressed_before_packaging: bool,
    pub require_reentry: bool,
    pub has_instructions: bool,
    pub has_sender_identity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryArtifactsManifest {
    pub instructions_file: Option<String>,
    pub sender_identity_file: Option<String>,
    pub runtime_entry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_identity_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderIdentityManifest {
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key_b64: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub device: Option<String>,
    pub created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryFileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSignature {
    pub algorithm: String,
    pub signature_b64: String,
    pub signed_fields: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<IntegrityInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureDeliveryManifest {
    pub schema_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_uuid: Option<String>,
    pub package_format: PackageFormat,
    pub created_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obsidianq_version: Option<String>,
    pub package_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_mode: Option<RecipientMode>,
    pub payload: PayloadManifest,
    pub options: DeliveryOptionsManifest,
    pub artifacts: DeliveryArtifactsManifest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<DeliveryFileEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<SenderIdentityManifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<ManifestSignature>,
}
