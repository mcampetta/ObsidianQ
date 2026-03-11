use serde::{Deserialize, Serialize};

pub const MANIFEST_FILE_NAME: &str = "secure_delivery_manifest.json";
pub const PAYLOAD_FILE_NAME: &str = "payload.obsq";
pub const INSTRUCTIONS_FILE_NAME: &str = "instructions.txt";
pub const PACKAGE_SUFFIX: &str = "_SecureDelivery";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageFormat {
    SecureDeliveryZip,
    SecureDeliveryExe,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureDeliveryManifestV1 {
    pub schema_version: u8,
    pub package_format: PackageFormat,
    pub created_utc: String,
    pub package_name: String,
    pub payload: PayloadManifest,
    pub options: DeliveryOptionsManifest,
    pub artifacts: DeliveryArtifactsManifest,
}

