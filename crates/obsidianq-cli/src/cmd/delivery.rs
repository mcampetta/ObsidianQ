use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{bail, Context, Result};
use base64ct::{Base64, Encoding};
use clap::{Args, Subcommand, ValueEnum};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use obsidianq_core::crypto::kdf::{self, Argon2Params};
use obsidianq_core::delivery::{
    DeliveryArtifactsManifest, DeliveryFileEntry, DeliveryOptionsManifest, IntegrityInfo,
    ManifestSignature, PackageFormat, PayloadManifest, RecipientMode, SecureDeliveryManifest,
    SenderIdentityManifest, INSTRUCTIONS_FILE_NAME, MANIFEST_FILE_NAME, PACKAGE_SUFFIX,
    PAYLOAD_FILE_NAME, SENDER_IDENTITY_FILE_NAME,
};
use obsidianq_core::engine::EncryptParams;
use obsidianq_core::format::{FileHeader, Mode, SuiteId};

use crate::public_identity::compute_fingerprint_b64;

#[derive(Args)]
pub struct DeliveryArgs {
    #[command(subcommand)]
    pub cmd: DeliveryCmd,
}

#[derive(Subcommand)]
pub enum DeliveryCmd {
    /// Create a Secure Delivery package
    Create(DeliveryCreateArgs),
    /// Inspect package metadata without decrypting
    Inspect(DeliveryInspectArgs),
    /// Verify package structure and payload integrity
    Verify(DeliveryVerifyArgs),
    /// Extract files from a Secure Delivery package
    Extract(DeliveryExtractArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DeliveryFormatArg {
    Zip,
    Exe,
}

#[derive(Args)]
pub struct DeliveryCreateArgs {
    /// Files and directories to include
    #[arg(required = true)]
    pub input: Vec<PathBuf>,

    /// Output directory
    #[arg(long)]
    pub output: PathBuf,

    /// Optional package base name
    #[arg(long)]
    pub name: Option<String>,

    /// Prompt for password
    #[arg(long, conflicts_with = "password_stdin")]
    pub password: bool,

    /// Read password from stdin (one line)
    #[arg(long, conflicts_with = "password")]
    pub password_stdin: bool,

    /// Delivery format (ZIP supported in M1)
    #[arg(long, default_value = "zip")]
    pub format: DeliveryFormatArg,

    /// Compress plaintext files in pre-encryption bundle
    #[arg(long)]
    pub compress: bool,

    /// Do not sign package metadata
    #[arg(long)]
    pub unsigned: bool,

    /// Omit sender name/email/device metadata while keeping signing available
    #[arg(long)]
    pub omit_sender_details: bool,

    /// Omit file list from package metadata and info views
    #[arg(long)]
    pub omit_file_list: bool,

    /// Omit app/version metadata from package metadata and info views
    #[arg(long)]
    pub omit_version_metadata: bool,

    /// Include instructions.txt
    #[arg(long)]
    pub include_instructions: bool,

    /// Load instructions text from a file
    #[arg(long = "instructions-file")]
    pub instructions_file: Option<PathBuf>,

    /// Allow replacing existing output package
    #[arg(long)]
    pub overwrite: bool,

    /// Emit machine-readable JSON response
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct DeliveryInspectArgs {
    pub package_path: PathBuf,

    /// Emit machine-readable JSON response
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct DeliveryVerifyArgs {
    pub package_path: PathBuf,

    /// Emit machine-readable JSON response
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct DeliveryExtractArgs {
    pub package_path: PathBuf,

    /// Destination directory for extracted files
    #[arg(long)]
    pub out: PathBuf,

    /// Prompt for password
    #[arg(long, conflicts_with = "password_stdin")]
    pub password: bool,

    /// Read password from stdin (one line)
    #[arg(long, conflicts_with = "password")]
    pub password_stdin: bool,

    /// Emit machine-readable JSON response
    #[arg(long)]
    pub json: bool,
}

struct SourceStats {
    source_item_count: usize,
    source_total_bytes: u64,
    files: Vec<DeliveryFileEntry>,
}

type DResult<T> = std::result::Result<T, DeliveryCliError>;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DeliveryErrorCode {
    InputNotFound,
    OutputInvalid,
    OutputExists,
    PasswordMissing,
    PasswordWeak,
    PasswordMismatch,
    ManifestInvalid,
    PayloadCorrupt,
    UnsupportedFormat,
    Internal,
}

impl DeliveryErrorCode {
    fn exit_code(self) -> i32 {
        match self {
            Self::InputNotFound
            | Self::OutputInvalid
            | Self::OutputExists
            | Self::PasswordMissing
            | Self::PasswordWeak
            | Self::PasswordMismatch
            | Self::UnsupportedFormat => 2,
            Self::ManifestInvalid | Self::PayloadCorrupt => 3,
            Self::Internal => 1,
        }
    }
}

#[derive(Debug, Serialize)]
struct DeliveryCliError {
    code: DeliveryErrorCode,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeliveryJsonResponse<T: Serialize> {
    ok: bool,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<DeliveryCliError>,
}

#[derive(Debug, Serialize)]
struct DeliveryCreateResponse {
    output_path: String,
    sha256: String,
    item_count: usize,
    payload_bytes: u64,
    package_bytes: u64,
}

#[derive(Debug, Serialize)]
struct DeliveryInspectResponse {
    schema_version: u8,
    package_uuid: Option<String>,
    package_format: String,
    created_utc: String,
    obsidianq_version: Option<String>,
    package_name: String,
    recipient_mode: Option<String>,
    payload_file: String,
    source_item_count: usize,
    source_total_bytes: u64,
    payload_sha256: String,
    has_instructions: bool,
    signed: bool,
    sender_fingerprint: Option<String>,
    sender_name: Option<String>,
    sender_email: Option<String>,
    sender_device: Option<String>,
    signature_algorithm: Option<String>,
    files: Vec<DeliveryFileEntry>,
}

#[derive(Debug, Serialize)]
struct DeliveryVerifyResponse {
    package_path: String,
    payload_sha256: String,
    signed: bool,
    sender_fingerprint: Option<String>,
    signature_algorithm: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeliveryExtractResponse {
    package_path: String,
    output_dir: String,
}

pub fn run(args: DeliveryArgs) -> Result<()> {
    match args.cmd {
        DeliveryCmd::Create(a) => emit_result("delivery.create", a.json, run_create(a), |r| {
            println!("Created Secure Delivery package: {}", r.output_path);
            println!("  Package: {} bytes", r.package_bytes);
            println!("  Payload: {} bytes", r.payload_bytes);
            println!("  Items  : {}", r.item_count);
            println!("  SHA-256: {}", r.sha256);
        }),
        DeliveryCmd::Inspect(a) => emit_result("delivery.inspect", a.json, run_inspect(a), |r| {
            println!("schema_version={}", r.schema_version);
            println!("package_uuid={}", r.package_uuid.as_deref().unwrap_or(""));
            println!("package_format={}", r.package_format);
            println!("created_utc={}", r.created_utc);
            println!(
                "obsidianq_version={}",
                r.obsidianq_version.as_deref().unwrap_or("")
            );
            println!("package_name={}", r.package_name);
            println!(
                "recipient_mode={}",
                r.recipient_mode.as_deref().unwrap_or("")
            );
            println!("payload_file={}", r.payload_file);
            println!("source_item_count={}", r.source_item_count);
            println!("source_total_bytes={}", r.source_total_bytes);
            println!("payload_sha256={}", r.payload_sha256);
            println!("has_instructions={}", r.has_instructions);
            println!("signed={}", r.signed);
            println!(
                "sender_fingerprint={}",
                r.sender_fingerprint.as_deref().unwrap_or("")
            );
            println!("sender_name={}", r.sender_name.as_deref().unwrap_or(""));
            println!("sender_email={}", r.sender_email.as_deref().unwrap_or(""));
            println!("sender_device={}", r.sender_device.as_deref().unwrap_or(""));
            println!(
                "signature_algorithm={}",
                r.signature_algorithm.as_deref().unwrap_or("")
            );
            println!("file_count={}", r.files.len());
        }),
        DeliveryCmd::Verify(a) => emit_result("delivery.verify", a.json, run_verify(a), |r| {
            println!("Package verified: {}", r.package_path);
            println!("  payload_sha256={}", r.payload_sha256);
            println!("  signed={}", r.signed);
            if let Some(fp) = &r.sender_fingerprint {
                println!("  sender_fingerprint={fp}");
            }
            if let Some(alg) = &r.signature_algorithm {
                println!("  signature_algorithm={alg}");
            }
        }),
        DeliveryCmd::Extract(a) => emit_result("delivery.extract", a.json, run_extract(a), |r| {
            println!("Extracted package: {}", r.package_path);
            println!("  Output: {}", r.output_dir);
        }),
    }
}

fn emit_result<T, F>(command: &str, json: bool, result: DResult<T>, print_human: F) -> Result<()>
where
    T: Serialize,
    F: FnOnce(&T),
{
    match result {
        Ok(data) => {
            if json {
                let out = DeliveryJsonResponse {
                    ok: true,
                    command: command.to_string(),
                    data: Some(data),
                    error: None,
                };
                println!("{}", serde_json::to_string(&out)?);
            } else {
                print_human(&data);
            }
            Ok(())
        }
        Err(err) => {
            if json {
                let out = DeliveryJsonResponse::<serde_json::Value> {
                    ok: false,
                    command: command.to_string(),
                    data: None,
                    error: Some(err),
                };
                println!("{}", serde_json::to_string(&out)?);
                process::exit(out.error.as_ref().map(|e| e.code.exit_code()).unwrap_or(1));
            }
            bail!("[{:?}] {}", err.code, err.message);
        }
    }
}

fn derr(
    code: DeliveryErrorCode,
    message: impl Into<String>,
    field: Option<&str>,
) -> DeliveryCliError {
    DeliveryCliError {
        code,
        message: message.into(),
        field: field.map(|s| s.to_string()),
    }
}

fn internal(message: impl Into<String>) -> DeliveryCliError {
    derr(DeliveryErrorCode::Internal, message, None)
}

fn run_create(args: DeliveryCreateArgs) -> DResult<DeliveryCreateResponse> {
    if !args.password && !args.password_stdin {
        return Err(derr(
            DeliveryErrorCode::PasswordMissing,
            "provide one of --password or --password-stdin",
            Some("password"),
        ));
    }
    if args.format == DeliveryFormatArg::Exe {
        return Err(derr(
            DeliveryErrorCode::UnsupportedFormat,
            "--format exe is not implemented yet (use --format zip)",
            Some("format"),
        ));
    }

    for p in &args.input {
        if !p.exists() {
            return Err(derr(
                DeliveryErrorCode::InputNotFound,
                format!("input not found: {}", p.display()),
                Some("input"),
            ));
        }
    }

    let package_name = derive_package_name(args.name, &args.input)
        .map_err(|e| internal(format!("derive package name: {e}")))?;
    fs::create_dir_all(&args.output).map_err(|e| {
        derr(
            DeliveryErrorCode::OutputInvalid,
            format!("create output dir {}: {e}", args.output.display()),
            Some("output"),
        )
    })?;

    let out_path = args
        .output
        .join(format!("{}{}.zip", package_name, PACKAGE_SUFFIX));
    if out_path.exists() && !args.overwrite {
        return Err(derr(
            DeliveryErrorCode::OutputExists,
            format!(
                "output already exists: {} (use --overwrite to replace)",
                out_path.display()
            ),
            Some("output"),
        ));
    }

    let password = get_password(args.password_stdin).map_err(|e| {
        if matches!(e.code, DeliveryErrorCode::PasswordMismatch) {
            e
        } else {
            derr(
                DeliveryErrorCode::PasswordMissing,
                e.message,
                Some("password"),
            )
        }
    })?;
    if password.trim().is_empty() {
        return Err(derr(
            DeliveryErrorCode::PasswordMissing,
            "password cannot be empty",
            Some("password"),
        ));
    }
    if password.chars().count() < 8 {
        return Err(derr(
            DeliveryErrorCode::PasswordWeak,
            "password too short: minimum length is 8 characters",
            Some("password"),
        ));
    }

    let staging =
        tempfile::tempdir().map_err(|e| internal(format!("create staging directory: {e}")))?;
    let bundle_path = staging.path().join("bundle_input.zip");
    let payload_path = staging.path().join(PAYLOAD_FILE_NAME);

    let source_stats = write_plain_bundle(&bundle_path, &args.input, args.compress)
        .map_err(|e| internal(format!("build plaintext bundle: {e}")))?;
    encrypt_bundle(&bundle_path, &payload_path, password.as_bytes())
        .map_err(|e| internal(format!("encrypt payload: {e}")))?;

    let payload_hash =
        sha256_file_hex(&payload_path).map_err(|e| internal(format!("hash payload: {e}")))?;
    let payload_len = fs::metadata(&payload_path)
        .map_err(|e| internal(format!("stat payload {}: {e}", payload_path.display())))?
        .len();
    let instructions_text = resolve_instructions(args.include_instructions, args.instructions_file)
        .map_err(|e| {
            derr(
                DeliveryErrorCode::OutputInvalid,
                format!("resolve instructions: {e}"),
                Some("instructions"),
            )
        })?;

    let instructions_hash = instructions_text
        .as_deref()
        .map(|text| sha256_bytes_hex(text.as_bytes()));

    let mut manifest = SecureDeliveryManifest {
        schema_version: 4,
        package_uuid: Some(generate_package_uuid()),
        package_format: PackageFormat::SecureDeliveryZip,
        created_utc: chrono::Utc::now().to_rfc3339(),
        obsidianq_version: if args.omit_version_metadata {
            None
        } else {
            Some(env!("CARGO_PKG_VERSION").to_string())
        },
        package_name: package_name.clone(),
        recipient_mode: Some(RecipientMode::Password),
        payload: PayloadManifest {
            file: PAYLOAD_FILE_NAME.to_string(),
            cipher_suite: "obsidianq_default".to_string(),
            integrity: IntegrityInfo {
                algorithm: "sha256".to_string(),
                hex: payload_hash.clone(),
            },
            source_item_count: source_stats.source_item_count,
            source_total_bytes: source_stats.source_total_bytes,
        },
        options: DeliveryOptionsManifest {
            compressed_before_packaging: args.compress,
            require_reentry: false,
            has_instructions: instructions_text.is_some(),
            has_sender_identity: false,
        },
        artifacts: DeliveryArtifactsManifest {
            instructions_file: instructions_text
                .as_ref()
                .map(|_| INSTRUCTIONS_FILE_NAME.to_string()),
            sender_identity_file: Some(SENDER_IDENTITY_FILE_NAME.to_string()),
            runtime_entry: None,
            instructions_sha256: instructions_hash,
            sender_identity_sha256: None,
        },
        files: if args.omit_file_list {
            Vec::new()
        } else {
            source_stats.files.clone()
        },
        sender: None,
        signature: None,
    };

    if args.unsigned {
        manifest.options.has_sender_identity = false;
        manifest.artifacts.sender_identity_file = None;
        manifest.artifacts.sender_identity_sha256 = None;
        write_delivery_zip(
            &out_path,
            &payload_path,
            &manifest,
            instructions_text.as_deref(),
            None,
        )
        .map_err(|e| internal(format!("write package zip: {e}")))?;
    } else {
        manifest.options.has_sender_identity = true;
    }

    if !args.unsigned {
        if let Some((sender_identity, signature)) =
            build_signed_manifest_parts(&mut manifest, !args.omit_sender_details)
                .map_err(|e| internal(format!("sign manifest: {e}")))?
        {
            manifest.signature = Some(signature);
            write_delivery_zip(
                &out_path,
                &payload_path,
                &manifest,
                instructions_text.as_deref(),
                Some(&sender_identity),
            )
            .map_err(|e| internal(format!("write package zip: {e}")))?;
        } else {
            manifest.options.has_sender_identity = false;
            manifest.artifacts.sender_identity_file = None;
            manifest.artifacts.sender_identity_sha256 = None;
            write_delivery_zip(
                &out_path,
                &payload_path,
                &manifest,
                instructions_text.as_deref(),
                None,
            )
            .map_err(|e| internal(format!("write package zip: {e}")))?;
        }
    }
    let output_size = fs::metadata(&out_path)
        .map_err(|e| internal(format!("stat package {}: {e}", out_path.display())))?
        .len();

    Ok(DeliveryCreateResponse {
        output_path: out_path.display().to_string(),
        sha256: payload_hash,
        item_count: source_stats.source_item_count,
        payload_bytes: payload_len,
        package_bytes: output_size,
    })
}

fn run_inspect(args: DeliveryInspectArgs) -> DResult<DeliveryInspectResponse> {
    let manifest = read_manifest(&args.package_path)
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    if !matches!(manifest.schema_version, 1 | 2 | 3 | 4) {
        return Err(derr(
            DeliveryErrorCode::ManifestInvalid,
            format!(
                "unsupported secure delivery schema version: {}",
                manifest.schema_version
            ),
            None,
        ));
    }
    let signature_info = verify_manifest_signature_for_package(&args.package_path, &manifest)
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    let sender = load_sender_identity_for_package(&args.package_path, &manifest)
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    Ok(DeliveryInspectResponse {
        schema_version: manifest.schema_version,
        package_uuid: manifest.package_uuid.clone(),
        package_format: format!("{:?}", manifest.package_format),
        created_utc: manifest.created_utc,
        obsidianq_version: manifest.obsidianq_version.clone(),
        package_name: manifest.package_name,
        recipient_mode: manifest.recipient_mode.as_ref().map(|m| format!("{:?}", m)),
        payload_file: manifest.payload.file,
        source_item_count: manifest.payload.source_item_count,
        source_total_bytes: manifest.payload.source_total_bytes,
        payload_sha256: manifest.payload.integrity.hex,
        has_instructions: manifest.options.has_instructions,
        signed: signature_info.signed,
        sender_fingerprint: sender.as_ref().map(|s| s.fingerprint.clone()),
        sender_name: sender.as_ref().and_then(|s| s.name.clone()),
        sender_email: sender.as_ref().and_then(|s| s.email.clone()),
        sender_device: sender.as_ref().and_then(|s| s.device.clone()),
        signature_algorithm: manifest.signature.as_ref().map(|s| s.algorithm.clone()),
        files: manifest.files.clone(),
    })
}

fn run_verify(args: DeliveryVerifyArgs) -> DResult<DeliveryVerifyResponse> {
    let manifest = read_manifest(&args.package_path)
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    if !matches!(manifest.schema_version, 1 | 2 | 3 | 4) {
        return Err(derr(
            DeliveryErrorCode::ManifestInvalid,
            format!(
                "unsupported secure delivery schema version: {}",
                manifest.schema_version
            ),
            None,
        ));
    }
    let signature_info = verify_manifest_signature_for_package(&args.package_path, &manifest)
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    let f = File::open(&args.package_path)
        .with_context(|| format!("open package {}", args.package_path.display()))
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    let mut zip = ZipArchive::new(f)
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    let mut payload = zip
        .by_name(PAYLOAD_FILE_NAME)
        .context("payload.obsq missing from package")
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    let mut hasher = Sha256::new();
    io::copy(&mut payload, &mut HashWrite(&mut hasher))
        .context("hash payload")
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    let actual = hex::encode(hasher.finalize());
    let expected = manifest.payload.integrity.hex.to_ascii_lowercase();
    if actual != expected {
        return Err(derr(
            DeliveryErrorCode::PayloadCorrupt,
            format!("payload hash mismatch: expected {expected}, got {actual}"),
            None,
        ));
    }

    Ok(DeliveryVerifyResponse {
        package_path: args.package_path.display().to_string(),
        payload_sha256: actual,
        signed: signature_info.signed,
        sender_fingerprint: load_sender_identity_for_package(&args.package_path, &manifest)
            .ok()
            .flatten()
            .map(|s| s.fingerprint),
        signature_algorithm: manifest.signature.as_ref().map(|s| s.algorithm.clone()),
    })
}

fn run_extract(args: DeliveryExtractArgs) -> DResult<DeliveryExtractResponse> {
    if !args.password && !args.password_stdin {
        return Err(derr(
            DeliveryErrorCode::PasswordMissing,
            "provide one of --password or --password-stdin",
            Some("password"),
        ));
    }

    let manifest = read_manifest(&args.package_path)
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    if !matches!(manifest.schema_version, 1 | 2 | 3 | 4) {
        return Err(derr(
            DeliveryErrorCode::ManifestInvalid,
            format!(
                "unsupported secure delivery schema version: {}",
                manifest.schema_version
            ),
            None,
        ));
    }
    verify_manifest_signature_for_package(&args.package_path, &manifest)
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    if !matches!(manifest.package_format, PackageFormat::SecureDeliveryZip) {
        return Err(derr(
            DeliveryErrorCode::UnsupportedFormat,
            format!(
                "unsupported package format for extract: {:?}",
                manifest.package_format
            ),
            Some("package"),
        ));
    }

    fs::create_dir_all(&args.out).map_err(|e| {
        derr(
            DeliveryErrorCode::OutputInvalid,
            format!("create output dir {}: {e}", args.out.display()),
            Some("out"),
        )
    })?;

    let password = get_password(args.password_stdin).map_err(|e| {
        if matches!(e.code, DeliveryErrorCode::PasswordMismatch) {
            e
        } else {
            derr(
                DeliveryErrorCode::PasswordMissing,
                e.message,
                Some("password"),
            )
        }
    })?;
    if password.is_empty() {
        return Err(derr(
            DeliveryErrorCode::PasswordMissing,
            "password cannot be empty",
            Some("password"),
        ));
    }

    let payload_bytes = read_payload_bytes(&args.package_path)
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    let plain_bundle = decrypt_payload_bytes(&payload_bytes, password.as_bytes()).map_err(|e| {
        derr(
            DeliveryErrorCode::PayloadCorrupt,
            format!("decrypt payload: {e}"),
            None,
        )
    })?;
    extract_plain_bundle_zip(&plain_bundle, &args.out).map_err(|e| {
        derr(
            DeliveryErrorCode::OutputInvalid,
            format!("extract bundle: {e}"),
            Some("out"),
        )
    })?;

    Ok(DeliveryExtractResponse {
        package_path: args.package_path.display().to_string(),
        output_dir: args.out.display().to_string(),
    })
}

fn derive_package_name(name: Option<String>, inputs: &[PathBuf]) -> Result<String> {
    let raw = if let Some(n) = name {
        n
    } else {
        let first = inputs
            .first()
            .and_then(|p| p.file_stem())
            .map(os_to_string)
            .transpose()?
            .unwrap_or_else(|| "package".to_string());
        first
    };
    let mut sanitized = raw
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            _ => c,
        })
        .collect::<String>()
        .trim()
        .trim_end_matches('.')
        .to_string();
    if sanitized.is_empty() {
        sanitized = "package".to_string();
    }
    Ok(sanitized)
}

fn get_password(from_stdin: bool) -> DResult<Zeroizing<String>> {
    if from_stdin {
        let mut raw = String::new();
        io::stdin()
            .read_line(&mut raw)
            .context("read password from stdin")
            .map_err(|e| {
                derr(
                    DeliveryErrorCode::PasswordMissing,
                    e.to_string(),
                    Some("password"),
                )
            })?;
        Ok(Zeroizing::new(
            raw.trim_end_matches(['\r', '\n']).to_string(),
        ))
    } else {
        let pw = Zeroizing::new(
            rpassword::prompt_password("Password: ")
                .context("password prompt")
                .map_err(|e| {
                    derr(
                        DeliveryErrorCode::PasswordMissing,
                        e.to_string(),
                        Some("password"),
                    )
                })?,
        );
        let confirm = Zeroizing::new(
            rpassword::prompt_password("Confirm  : ")
                .context("confirm prompt")
                .map_err(|e| {
                    derr(
                        DeliveryErrorCode::PasswordMissing,
                        e.to_string(),
                        Some("password"),
                    )
                })?,
        );
        if *pw != *confirm {
            return Err(derr(
                DeliveryErrorCode::PasswordMismatch,
                "passwords do not match",
                Some("password_confirm"),
            ));
        }
        Ok(pw)
    }
}

fn write_plain_bundle(path: &Path, inputs: &[PathBuf], compress: bool) -> Result<SourceStats> {
    let out = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut zip = ZipWriter::new(out);
    let method = if compress {
        CompressionMethod::Deflated
    } else {
        CompressionMethod::Stored
    };
    let options = SimpleFileOptions::default().compression_method(method);

    let mut stats = SourceStats {
        source_item_count: 0,
        source_total_bytes: 0,
        files: Vec::new(),
    };
    for src in inputs {
        add_path_to_zip(&mut zip, src, &mut stats, options)?;
    }
    zip.finish().context("finalize plaintext bundle zip")?;
    Ok(stats)
}

fn add_path_to_zip(
    zip: &mut ZipWriter<File>,
    src: &Path,
    stats: &mut SourceStats,
    options: SimpleFileOptions,
) -> Result<()> {
    let src_name = src
        .file_name()
        .map(os_to_string)
        .transpose()?
        .unwrap_or_else(|| "input".to_string());
    if src.is_file() {
        add_file(zip, src, &PathBuf::from(&src_name), stats, options)?;
        return Ok(());
    }
    if !src.is_dir() {
        bail!("unsupported source type: {}", src.display());
    }
    add_dir_recursive(zip, src, &PathBuf::from(src_name), stats, options)
}

fn add_dir_recursive(
    zip: &mut ZipWriter<File>,
    root: &Path,
    rel: &Path,
    stats: &mut SourceStats,
    options: SimpleFileOptions,
) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("read dir {}", root.display()))? {
        let entry = entry?;
        let p = entry.path();
        let rel_path = rel.join(entry.file_name());
        if p.is_dir() {
            add_dir_recursive(zip, &p, &rel_path, stats, options)?;
        } else if p.is_file() {
            add_file(zip, &p, &rel_path, stats, options)?;
        }
    }
    Ok(())
}

fn add_file(
    zip: &mut ZipWriter<File>,
    source: &Path,
    rel_path: &Path,
    stats: &mut SourceStats,
    options: SimpleFileOptions,
) -> Result<()> {
    let rel = path_to_zip_name(rel_path);
    zip.start_file(&rel, options)
        .with_context(|| format!("add zip entry {}", source.display()))?;
    let mut f = File::open(source).with_context(|| format!("open {}", source.display()))?;
    let mut hasher = Sha256::new();
    let mut n = 0u64;
    let mut buf = [0u8; 8192];
    loop {
        let read = f
            .read(&mut buf)
            .with_context(|| format!("read {}", source.display()))?;
        if read == 0 {
            break;
        }
        zip.write_all(&buf[..read])
            .with_context(|| format!("copy {}", source.display()))?;
        hasher.update(&buf[..read]);
        n += read as u64;
    }
    stats.source_item_count += 1;
    stats.source_total_bytes += n;
    stats.files.push(DeliveryFileEntry {
        path: rel,
        size: n,
        sha256: hex::encode(hasher.finalize()),
    });
    Ok(())
}

fn encrypt_bundle(input_bundle: &Path, payload: &Path, password: &[u8]) -> Result<()> {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let master_key = kdf::derive_password_key(password, &salt, &Argon2Params::default())
        .context("derive password key")?;

    let mut file_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut file_id);

    let params = EncryptParams {
        master_key,
        kem_data: salt.to_vec(),
        mode: Mode::Password,
        suite: SuiteId::XChaCha20Poly1305,
        chunk_size: obsidianq_core::DEFAULT_CHUNK_SIZE,
        compress: false,
        file_id,
    };

    let mut reader = io::BufReader::new(
        File::open(input_bundle)
            .with_context(|| format!("open plaintext bundle {}", input_bundle.display()))?,
    );
    let mut writer = io::BufWriter::new(
        File::create(payload).with_context(|| format!("create payload {}", payload.display()))?,
    );
    obsidianq_core::encrypt(params, &mut reader, &mut writer).context("encrypt payload")?;
    writer.flush().context("flush payload output")?;
    Ok(())
}

fn write_delivery_zip(
    out_path: &Path,
    payload_path: &Path,
    manifest: &SecureDeliveryManifest,
    instructions: Option<&str>,
    sender_identity: Option<&SenderIdentityManifest>,
) -> Result<()> {
    let out = File::create(out_path).with_context(|| format!("create {}", out_path.display()))?;
    let mut zip = ZipWriter::new(out);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    zip.start_file(MANIFEST_FILE_NAME, options)
        .context("write manifest entry")?;
    let manifest_json = serde_json::to_vec_pretty(manifest).context("serialize manifest")?;
    zip.write_all(&manifest_json)
        .context("write manifest data")?;

    zip.start_file(PAYLOAD_FILE_NAME, options)
        .context("write payload entry")?;
    let mut payload_file = File::open(payload_path).context("open payload")?;
    io::copy(&mut payload_file, &mut zip).context("copy payload into package")?;

    if let Some(text) = instructions {
        zip.start_file(INSTRUCTIONS_FILE_NAME, options)
            .context("write instructions entry")?;
        zip.write_all(text.as_bytes())
            .context("write instructions text")?;
    }

    if let Some(identity) = sender_identity {
        zip.start_file(SENDER_IDENTITY_FILE_NAME, options)
            .context("write sender identity entry")?;
        let identity_json =
            serde_json::to_vec_pretty(identity).context("serialize sender identity")?;
        zip.write_all(&identity_json)
            .context("write sender identity data")?;
    }

    zip.finish().context("finalize package zip")?;
    Ok(())
}

fn read_manifest(package_path: &Path) -> Result<SecureDeliveryManifest> {
    let f = File::open(package_path).with_context(|| format!("open {}", package_path.display()))?;
    let mut zip = ZipArchive::new(f).context("read package zip")?;
    let mut manifest_file = zip
        .by_name(MANIFEST_FILE_NAME)
        .context("secure delivery manifest missing")?;
    let mut data = Vec::new();
    manifest_file
        .read_to_end(&mut data)
        .context("read manifest")?;
    serde_json::from_slice(&data).context("parse manifest json")
}

#[derive(Debug, Clone, Copy)]
struct SignatureVerifyInfo {
    signed: bool,
}

fn build_signed_manifest_parts(
    manifest: &mut SecureDeliveryManifest,
    include_sender_details: bool,
) -> Result<Option<(SenderIdentityManifest, ManifestSignature)>> {
    let Some((signing_key, sender_identity)) =
        load_or_create_signing_identity(include_sender_details)?
    else {
        return Ok(None);
    };
    let sender_identity_json =
        serde_json::to_vec_pretty(&sender_identity).context("serialize sender identity")?;
    manifest.artifacts.sender_identity_sha256 = Some(sha256_bytes_hex(&sender_identity_json));
    let signed_fields = "manifest-v3".to_string();
    let msg = canonical_manifest_bytes(manifest, &signed_fields)?;
    let manifest_hash = sha256_bytes_hex(&msg);
    let signature = signing_key.sign(&msg);
    Ok(Some((
        sender_identity,
        ManifestSignature {
            algorithm: "ed25519".to_string(),
            signature_b64: Base64::encode_string(&signature.to_bytes()),
            signed_fields,
            manifest_hash: Some(IntegrityInfo {
                algorithm: "sha256".to_string(),
                hex: manifest_hash,
            }),
        },
    )))
}

fn verify_manifest_signature_for_package(
    package_path: &Path,
    manifest: &SecureDeliveryManifest,
) -> Result<SignatureVerifyInfo> {
    match &manifest.signature {
        None => Ok(SignatureVerifyInfo { signed: false }),
        Some(signature) => {
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
            let sender = load_sender_identity_for_package(package_path, manifest)?
                .context("sender identity missing from signed package")?;
            let public_key = Base64::decode_vec(&sender.public_key_b64)
                .map_err(|e| anyhow::anyhow!("invalid sender public key base64: {e}"))?;
            if public_key.len() != 32 {
                bail!(
                    "invalid sender public key length: expected 32, got {}",
                    public_key.len()
                );
            }
            let expected_fp = compute_fingerprint_b64(&public_key);
            if !expected_fp.eq_ignore_ascii_case(&sender.fingerprint) {
                bail!("sender fingerprint does not match sender public key");
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
            let sig = Signature::from_slice(&sig_bytes)
                .map_err(|e| anyhow::anyhow!("parse signature: {e}"))?;
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
            Ok(SignatureVerifyInfo { signed: true })
        }
    }
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

fn load_sender_identity_for_package(
    package_path: &Path,
    manifest: &SecureDeliveryManifest,
) -> Result<Option<SenderIdentityManifest>> {
    if let Some(sender) = manifest.sender.clone() {
        return Ok(Some(sender));
    }
    let Some(identity_file) = manifest.artifacts.sender_identity_file.as_deref() else {
        return Ok(None);
    };
    let data = read_zip_entry_bytes(package_path, identity_file)
        .with_context(|| format!("read sender identity entry {identity_file}"))?;
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

fn read_zip_entry_bytes(package_path: &Path, entry_name: &str) -> Result<Vec<u8>> {
    let f = File::open(package_path).with_context(|| format!("open {}", package_path.display()))?;
    let mut zip = ZipArchive::new(f).context("read package zip")?;
    let mut entry = zip
        .by_name(entry_name)
        .with_context(|| format!("{entry_name} missing from package"))?;
    let mut data = Vec::new();
    entry
        .read_to_end(&mut data)
        .with_context(|| format!("read {entry_name}"))?;
    Ok(data)
}

fn load_or_create_signing_identity(
    include_sender_details: bool,
) -> Result<Option<(SigningKey, SenderIdentityManifest)>> {
    let private_path = signing_private_key_path();
    let public_path = signing_public_key_path();

    if private_path.exists() {
        let raw = fs::read(&private_path)
            .with_context(|| format!("read signing key {}", private_path.display()))?;
        if raw.len() != 32 {
            bail!(
                "invalid signing private key length in {}: expected 32, got {}",
                private_path.display(),
                raw.len()
            );
        }
        let secret: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signing key bytes"))?;
        let signing_key = SigningKey::from_bytes(&secret);
        let sender = build_sender_identity(&signing_key.verifying_key(), include_sender_details)?;
        if !public_path.exists() {
            if let Some(parent) = public_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create signing key dir {}", parent.display()))?;
            }
            fs::write(&public_path, signing_key.verifying_key().to_bytes())
                .with_context(|| format!("write signing pubkey {}", public_path.display()))?;
        }
        return Ok(Some((signing_key, sender)));
    }

    if let Some(parent) = private_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create signing key dir {}", parent.display()))?;
    }
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    fs::write(&private_path, signing_key.to_bytes())
        .with_context(|| format!("write signing key {}", private_path.display()))?;
    fs::write(&public_path, signing_key.verifying_key().to_bytes())
        .with_context(|| format!("write signing pubkey {}", public_path.display()))?;
    let sender = build_sender_identity(&signing_key.verifying_key(), include_sender_details)?;
    Ok(Some((signing_key, sender)))
}

fn build_sender_identity(
    verifying_key: &VerifyingKey,
    include_sender_details: bool,
) -> Result<SenderIdentityManifest> {
    let public_key = verifying_key.to_bytes();
    let meta = if include_sender_details {
        load_default_identity_metadata()?
    } else {
        None
    };
    Ok(SenderIdentityManifest {
        algorithm: "ed25519".to_string(),
        fingerprint: compute_fingerprint_b64(&public_key),
        public_key_b64: Base64::encode_string(&public_key),
        name: meta.as_ref().and_then(|m| m.name.clone()),
        email: meta.as_ref().and_then(|m| m.email.clone()),
        device: meta.as_ref().and_then(|m| m.device.clone()),
        created: meta
            .and_then(|m| m.created)
            .or_else(|| Some(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string())),
    })
}

#[derive(Debug, Clone)]
struct LocalIdentityMeta {
    name: Option<String>,
    email: Option<String>,
    device: Option<String>,
    created: Option<String>,
}

fn load_default_identity_metadata() -> Result<Option<LocalIdentityMeta>> {
    let profile_path = app_data_dir().join("identity_profile_v1.tsv");
    if profile_path.exists() {
        let profile_text = fs::read_to_string(&profile_path)
            .with_context(|| format!("read {}", profile_path.display()))?;
        let parts: Vec<&str> = profile_text.split('\t').collect();
        let name = parts.first().and_then(|v| clean_meta(v));
        let email = parts.get(1).and_then(|v| clean_meta(v));
        let device = parts.get(2).and_then(|v| clean_meta(v));
        if name.is_some() || email.is_some() || device.is_some() {
            return Ok(Some(LocalIdentityMeta {
                name,
                email,
                device,
                created: None,
            }));
        }
    }

    let path = app_data_dir().join("public_identity_meta_v1.tsv");
    if !path.exists() {
        return Ok(None);
    }
    for line in fs::read_to_string(&path)
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
        return Ok(Some(LocalIdentityMeta {
            name: clean_meta(parts[1]),
            email: clean_meta(parts[2]),
            device: clean_meta(parts[3]),
            created: clean_meta(parts[4]),
        }));
    }
    Ok(None)
}

fn signing_private_key_path() -> PathBuf {
    app_data_dir()
        .join("keys")
        .join("obsidianq_signing_ed25519.key")
}

fn signing_public_key_path() -> PathBuf {
    app_data_dir()
        .join("keys")
        .join("obsidianq_signing_ed25519.pub")
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

fn clean_meta(v: &str) -> Option<String> {
    let t = v.trim().trim_start_matches('\u{feff}');
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn read_payload_bytes(package_path: &Path) -> Result<Vec<u8>> {
    let f = File::open(package_path).with_context(|| format!("open {}", package_path.display()))?;
    let mut zip = ZipArchive::new(f).context("read package zip")?;
    let mut payload_file = zip
        .by_name(PAYLOAD_FILE_NAME)
        .context("payload.obsq missing from package")?;
    let mut data = Vec::new();
    payload_file
        .read_to_end(&mut data)
        .context("read payload.obsq from package")?;
    Ok(data)
}

fn decrypt_payload_bytes(payload: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(payload);
    let header = FileHeader::read_from(&mut cursor).context("parse payload header")?;
    if !matches!(header.mode, Mode::Password) {
        bail!("secure delivery payload is not in password mode");
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

    let mut decrypt_in = std::io::Cursor::new(payload);
    let mut plain = Vec::new();
    obsidianq_core::decrypt(&master_key, &mut decrypt_in, &mut plain).context("decrypt payload")?;
    Ok(plain)
}

fn extract_plain_bundle_zip(plain_zip_bytes: &[u8], out_dir: &Path) -> Result<()> {
    let cursor = std::io::Cursor::new(plain_zip_bytes);
    let mut bundle = ZipArchive::new(cursor).context("read plaintext bundle zip")?;
    for i in 0..bundle.len() {
        let mut entry = bundle
            .by_index(i)
            .with_context(|| format!("read bundle entry {i}"))?;
        let enclosed = entry
            .enclosed_name()
            .context("bundle contains unsafe path entry")?;
        let out_path = out_dir.join(enclosed);

        if entry.is_dir() {
            fs::create_dir_all(&out_path)
                .with_context(|| format!("create dir {}", out_path.display()))?;
            continue;
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        let mut out =
            File::create(&out_path).with_context(|| format!("create {}", out_path.display()))?;
        io::copy(&mut entry, &mut out).with_context(|| format!("write {}", out_path.display()))?;
    }
    Ok(())
}

fn resolve_instructions(include: bool, path: Option<PathBuf>) -> Result<Option<String>> {
    if !include {
        return Ok(None);
    }
    if let Some(p) = path {
        let text = fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
        return Ok(Some(text));
    }
    Ok(Some(
        "1) Open the package\n2) Enter the password\n3) Choose extract location\n4) Open your files\n"
            .to_string(),
    ))
}

fn sha256_file_hex(path: &Path) -> Result<String> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_bytes_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn generate_package_uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn os_to_string(v: &std::ffi::OsStr) -> Result<String> {
    v.to_str()
        .map(|s| s.to_string())
        .with_context(|| format!("invalid UTF-8 path component {:?}", OsString::from(v)))
}

fn path_to_zip_name(p: &Path) -> String {
    p.components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

struct HashWrite<'a, D: Digest>(&'a mut D);
impl<D: Digest> Write for HashWrite<'_, D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn package_name_sanitizes() {
        let got = derive_package_name(Some("a:b*c?".to_string()), &[]).expect("derive");
        assert_eq!(got, "a_b_c_");
    }

    #[test]
    fn zip_name_uses_forward_slashes() {
        let p = PathBuf::from("one").join("two").join("three.txt");
        assert_eq!(path_to_zip_name(&p), "one/two/three.txt");
    }

    #[test]
    fn clean_meta_strips_utf8_bom() {
        assert_eq!(clean_meta("\u{feff}Martin"), Some("Martin".to_string()));
        assert_eq!(
            clean_meta("  \u{feff}martin@example.com  "),
            Some("martin@example.com".to_string())
        );
    }

    #[test]
    fn create_and_verify_manifest_roundtrip() {
        let td = tempfile::tempdir().expect("tmp");
        let in_file = td.path().join("hello.txt");
        let mut f = File::create(&in_file).expect("create input");
        writeln!(f, "hello world").expect("write input");
        drop(f);

        let out_dir = td.path().join("out");
        let args = DeliveryCreateArgs {
            input: vec![in_file],
            output: out_dir.clone(),
            name: Some("demo".to_string()),
            password: false,
            password_stdin: true,
            format: DeliveryFormatArg::Zip,
            compress: false,
            unsigned: false,
            omit_sender_details: false,
            omit_file_list: false,
            omit_version_metadata: false,
            include_instructions: true,
            instructions_file: None,
            overwrite: true,
            json: false,
        };

        let _ = args;
        // Command path isn't invoked in test (stdin dependency), but core packaging helpers are exercised below.
        fs::create_dir_all(&out_dir).expect("create out dir");
        let staging = tempfile::tempdir().expect("create staging");
        let plain = staging.path().join("bundle.zip");
        let payload = staging.path().join(PAYLOAD_FILE_NAME);
        let stats =
            write_plain_bundle(&plain, &[td.path().join("hello.txt")], false).expect("bundle");
        assert_eq!(stats.source_item_count, 1);
        encrypt_bundle(&plain, &payload, b"1234567890").expect("encrypt");
        let hash = sha256_file_hex(&payload).expect("hash payload");
        let manifest = SecureDeliveryManifest {
            schema_version: 4,
            package_uuid: Some("11111111-1111-4111-8111-111111111111".to_string()),
            package_format: PackageFormat::SecureDeliveryZip,
            created_utc: "2026-01-01T00:00:00Z".to_string(),
            obsidianq_version: Some("1.3.0".to_string()),
            package_name: "demo".to_string(),
            recipient_mode: Some(RecipientMode::Password),
            payload: PayloadManifest {
                file: PAYLOAD_FILE_NAME.to_string(),
                cipher_suite: "obsidianq_default".to_string(),
                integrity: IntegrityInfo {
                    algorithm: "sha256".to_string(),
                    hex: hash.clone(),
                },
                source_item_count: 1,
                source_total_bytes: 11,
            },
            options: DeliveryOptionsManifest {
                compressed_before_packaging: false,
                require_reentry: false,
                has_instructions: true,
                has_sender_identity: false,
            },
            artifacts: DeliveryArtifactsManifest {
                instructions_file: Some(INSTRUCTIONS_FILE_NAME.to_string()),
                sender_identity_file: None,
                runtime_entry: None,
                instructions_sha256: Some(sha256_bytes_hex("test instructions".as_bytes())),
                sender_identity_sha256: None,
            },
            files: stats.files.clone(),
            sender: None,
            signature: None,
        };
        let out_zip = out_dir.join("demo_SecureDelivery.zip");
        write_delivery_zip(
            &out_zip,
            &payload,
            &manifest,
            Some("test instructions"),
            None,
        )
        .expect("write package");
        let parsed = read_manifest(&out_zip).expect("read manifest");
        assert_eq!(parsed.package_name, "demo");
        assert_eq!(parsed.payload.integrity.hex, hash);
    }

    #[test]
    fn create_then_extract_roundtrip() {
        let td = tempfile::tempdir().expect("tmp");
        let src_dir = td.path().join("src");
        fs::create_dir_all(&src_dir).expect("create src dir");
        let src_file = src_dir.join("note.txt");
        fs::write(&src_file, b"secure delivery data").expect("write source");

        let staging = tempfile::tempdir().expect("staging");
        let plain = staging.path().join("bundle.zip");
        let payload = staging.path().join(PAYLOAD_FILE_NAME);
        let stats =
            write_plain_bundle(&plain, std::slice::from_ref(&src_dir), false).expect("bundle");
        assert_eq!(stats.source_item_count, 1);
        encrypt_bundle(&plain, &payload, b"1234567890").expect("encrypt");
        let hash = sha256_file_hex(&payload).expect("hash");
        let out_zip = td.path().join("demo_SecureDelivery.zip");
        let manifest = SecureDeliveryManifest {
            schema_version: 4,
            package_uuid: Some("22222222-2222-4222-8222-222222222222".to_string()),
            package_format: PackageFormat::SecureDeliveryZip,
            created_utc: "2026-01-01T00:00:00Z".to_string(),
            obsidianq_version: Some("1.3.0".to_string()),
            package_name: "demo".to_string(),
            recipient_mode: Some(RecipientMode::Password),
            payload: PayloadManifest {
                file: PAYLOAD_FILE_NAME.to_string(),
                cipher_suite: "obsidianq_default".to_string(),
                integrity: IntegrityInfo {
                    algorithm: "sha256".to_string(),
                    hex: hash,
                },
                source_item_count: stats.source_item_count,
                source_total_bytes: stats.source_total_bytes,
            },
            options: DeliveryOptionsManifest {
                compressed_before_packaging: false,
                require_reentry: false,
                has_instructions: false,
                has_sender_identity: false,
            },
            artifacts: DeliveryArtifactsManifest {
                instructions_file: None,
                sender_identity_file: None,
                runtime_entry: None,
                instructions_sha256: None,
                sender_identity_sha256: None,
            },
            files: stats.files.clone(),
            sender: None,
            signature: None,
        };
        write_delivery_zip(&out_zip, &payload, &manifest, None, None).expect("package write");
        let payload_bytes = read_payload_bytes(&out_zip).expect("read payload");
        let plain_bundle =
            decrypt_payload_bytes(&payload_bytes, b"1234567890").expect("decrypt payload");
        let extracted = td.path().join("extracted");
        extract_plain_bundle_zip(&plain_bundle, &extracted).expect("extract");

        let extracted_file = extracted.join("src").join("note.txt");
        let actual = fs::read_to_string(extracted_file).expect("read extracted");
        assert_eq!(actual, "secure delivery data");
    }

    #[test]
    fn signed_manifest_verification_detects_tamper() {
        let td = tempfile::tempdir().expect("tmp");
        std::env::set_var("LOCALAPPDATA", td.path());

        let mut base = SecureDeliveryManifest {
            schema_version: 4,
            package_uuid: Some("33333333-3333-4333-8333-333333333333".to_string()),
            package_format: PackageFormat::SecureDeliveryZip,
            created_utc: "2026-03-12T00:00:00Z".to_string(),
            obsidianq_version: Some("1.3.0".to_string()),
            package_name: "demo".to_string(),
            recipient_mode: Some(RecipientMode::Password),
            payload: PayloadManifest {
                file: PAYLOAD_FILE_NAME.to_string(),
                cipher_suite: "obsidianq_default".to_string(),
                integrity: IntegrityInfo {
                    algorithm: "sha256".to_string(),
                    hex: "abc123".to_string(),
                },
                source_item_count: 1,
                source_total_bytes: 99,
            },
            options: DeliveryOptionsManifest {
                compressed_before_packaging: false,
                require_reentry: false,
                has_instructions: false,
                has_sender_identity: true,
            },
            artifacts: DeliveryArtifactsManifest {
                instructions_file: None,
                sender_identity_file: Some(SENDER_IDENTITY_FILE_NAME.to_string()),
                runtime_entry: None,
                instructions_sha256: None,
                sender_identity_sha256: None,
            },
            files: vec![DeliveryFileEntry {
                path: "hello.txt".to_string(),
                size: 99,
                sha256: "abc123".to_string(),
            }],
            sender: None,
            signature: None,
        };

        let (sender, signature) = build_signed_manifest_parts(&mut base, true)
            .expect("sign")
            .expect("signature parts");
        let mut signed = base.clone();
        signed.signature = Some(signature);
        let out_zip = td.path().join("signed.zip");
        let payload = td.path().join(PAYLOAD_FILE_NAME);
        fs::write(&payload, b"payload").expect("write payload");
        write_delivery_zip(&out_zip, &payload, &signed, None, Some(&sender))
            .expect("write signed package");

        let info = verify_manifest_signature_for_package(&out_zip, &signed).expect("verify");
        assert!(info.signed);

        signed.package_name = "tampered".to_string();
        assert!(verify_manifest_signature_for_package(&out_zip, &signed).is_err());
    }
}
