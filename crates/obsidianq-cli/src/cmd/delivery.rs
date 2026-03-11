use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use obsidianq_core::crypto::kdf::{self, Argon2Params};
use obsidianq_core::delivery::{
    DeliveryArtifactsManifest, DeliveryOptionsManifest, INSTRUCTIONS_FILE_NAME, IntegrityInfo,
    MANIFEST_FILE_NAME, PACKAGE_SUFFIX, PAYLOAD_FILE_NAME, PackageFormat, PayloadManifest,
    SecureDeliveryManifestV1,
};
use obsidianq_core::engine::EncryptParams;
use obsidianq_core::format::{FileHeader, Mode, SuiteId};

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
    package_format: String,
    created_utc: String,
    package_name: String,
    payload_file: String,
    source_item_count: usize,
    source_total_bytes: u64,
    payload_sha256: String,
    has_instructions: bool,
}

#[derive(Debug, Serialize)]
struct DeliveryVerifyResponse {
    package_path: String,
    payload_sha256: String,
}

#[derive(Debug, Serialize)]
struct DeliveryExtractResponse {
    package_path: String,
    output_dir: String,
}

pub fn run(args: DeliveryArgs) -> Result<()> {
    match args.cmd {
        DeliveryCmd::Create(a) => emit_result(
            "delivery.create",
            a.json,
            run_create(a),
            |r| {
                println!("Created Secure Delivery package: {}", r.output_path);
                println!("  Package: {} bytes", r.package_bytes);
                println!("  Payload: {} bytes", r.payload_bytes);
                println!("  Items  : {}", r.item_count);
                println!("  SHA-256: {}", r.sha256);
            },
        ),
        DeliveryCmd::Inspect(a) => emit_result(
            "delivery.inspect",
            a.json,
            run_inspect(a),
            |r| {
                println!("schema_version={}", r.schema_version);
                println!("package_format={}", r.package_format);
                println!("created_utc={}", r.created_utc);
                println!("package_name={}", r.package_name);
                println!("payload_file={}", r.payload_file);
                println!("source_item_count={}", r.source_item_count);
                println!("source_total_bytes={}", r.source_total_bytes);
                println!("payload_sha256={}", r.payload_sha256);
                println!("has_instructions={}", r.has_instructions);
            },
        ),
        DeliveryCmd::Verify(a) => emit_result(
            "delivery.verify",
            a.json,
            run_verify(a),
            |r| {
                println!("Package verified: {}", r.package_path);
                println!("  payload_sha256={}", r.payload_sha256);
            },
        ),
        DeliveryCmd::Extract(a) => emit_result(
            "delivery.extract",
            a.json,
            run_extract(a),
            |r| {
                println!("Extracted package: {}", r.package_path);
                println!("  Output: {}", r.output_dir);
            },
        ),
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

fn derr(code: DeliveryErrorCode, message: impl Into<String>, field: Option<&str>) -> DeliveryCliError {
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

    let staging = tempfile::tempdir().map_err(|e| internal(format!("create staging directory: {e}")))?;
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
    let instructions_text =
        resolve_instructions(args.include_instructions, args.instructions_file).map_err(|e| {
            derr(
                DeliveryErrorCode::OutputInvalid,
                format!("resolve instructions: {e}"),
                Some("instructions"),
            )
        })?;

    let manifest = SecureDeliveryManifestV1 {
        schema_version: 1,
        package_format: PackageFormat::SecureDeliveryZip,
        created_utc: chrono::Utc::now().to_rfc3339(),
        package_name: package_name.clone(),
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
            sender_identity_file: None,
            runtime_entry: None,
        },
    };

    write_delivery_zip(&out_path, &payload_path, &manifest, instructions_text.as_deref())
        .map_err(|e| internal(format!("write package zip: {e}")))?;
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
    if manifest.schema_version != 1 {
        return Err(derr(
            DeliveryErrorCode::ManifestInvalid,
            format!(
                "unsupported secure delivery schema version: {}",
                manifest.schema_version
            ),
            None,
        ));
    }
    Ok(DeliveryInspectResponse {
        schema_version: manifest.schema_version,
        package_format: format!("{:?}", manifest.package_format),
        created_utc: manifest.created_utc,
        package_name: manifest.package_name,
        payload_file: manifest.payload.file,
        source_item_count: manifest.payload.source_item_count,
        source_total_bytes: manifest.payload.source_total_bytes,
        payload_sha256: manifest.payload.integrity.hex,
        has_instructions: manifest.options.has_instructions,
    })
}

fn run_verify(args: DeliveryVerifyArgs) -> DResult<DeliveryVerifyResponse> {
    let manifest = read_manifest(&args.package_path)
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    if manifest.schema_version != 1 {
        return Err(derr(
            DeliveryErrorCode::ManifestInvalid,
            format!(
                "unsupported secure delivery schema version: {}",
                manifest.schema_version
            ),
            None,
        ));
    }
    let f = File::open(&args.package_path)
        .with_context(|| format!("open package {}", args.package_path.display()))
        .map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
    let mut zip =
        ZipArchive::new(f).map_err(|e| derr(DeliveryErrorCode::ManifestInvalid, e.to_string(), None))?;
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
    if manifest.schema_version != 1 {
        return Err(derr(
            DeliveryErrorCode::ManifestInvalid,
            format!(
                "unsupported secure delivery schema version: {}",
                manifest.schema_version
            ),
            None,
        ));
    }
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
            .map_err(|e| derr(DeliveryErrorCode::PasswordMissing, e.to_string(), Some("password")))?;
        Ok(Zeroizing::new(
            raw.trim_end_matches(['\r', '\n']).to_string(),
        ))
    } else {
        let pw = Zeroizing::new(
            rpassword::prompt_password("Password: ")
                .context("password prompt")
                .map_err(|e| derr(DeliveryErrorCode::PasswordMissing, e.to_string(), Some("password")))?,
        );
        let confirm = Zeroizing::new(
            rpassword::prompt_password("Confirm  : ")
                .context("confirm prompt")
                .map_err(|e| derr(DeliveryErrorCode::PasswordMissing, e.to_string(), Some("password")))?,
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
    zip.start_file(rel, options)
        .with_context(|| format!("add zip entry {}", source.display()))?;
    let mut f = File::open(source).with_context(|| format!("open {}", source.display()))?;
    let n = io::copy(&mut f, zip).with_context(|| format!("copy {}", source.display()))?;
    stats.source_item_count += 1;
    stats.source_total_bytes += n;
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
    manifest: &SecureDeliveryManifestV1,
    instructions: Option<&str>,
) -> Result<()> {
    let out = File::create(out_path).with_context(|| format!("create {}", out_path.display()))?;
    let mut zip = ZipWriter::new(out);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    zip.start_file(MANIFEST_FILE_NAME, options)
        .context("write manifest entry")?;
    let manifest_json = serde_json::to_vec_pretty(manifest).context("serialize manifest")?;
    zip.write_all(&manifest_json).context("write manifest data")?;

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

    zip.finish().context("finalize package zip")?;
    Ok(())
}

fn read_manifest(package_path: &Path) -> Result<SecureDeliveryManifestV1> {
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
        let mut entry = bundle.by_index(i).with_context(|| format!("read bundle entry {i}"))?;
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
        let stats = write_plain_bundle(&plain, &[td.path().join("hello.txt")], false).expect("bundle");
        assert_eq!(stats.source_item_count, 1);
        encrypt_bundle(&plain, &payload, b"1234567890").expect("encrypt");
        let hash = sha256_file_hex(&payload).expect("hash payload");
        let manifest = SecureDeliveryManifestV1 {
            schema_version: 1,
            package_format: PackageFormat::SecureDeliveryZip,
            created_utc: "2026-01-01T00:00:00Z".to_string(),
            package_name: "demo".to_string(),
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
            },
        };
        let out_zip = out_dir.join("demo_SecureDelivery.zip");
        write_delivery_zip(&out_zip, &payload, &manifest, Some("test instructions")).expect("write package");
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
        let stats = write_plain_bundle(&plain, std::slice::from_ref(&src_dir), false).expect("bundle");
        assert_eq!(stats.source_item_count, 1);
        encrypt_bundle(&plain, &payload, b"1234567890").expect("encrypt");
        let hash = sha256_file_hex(&payload).expect("hash");
        let out_zip = td.path().join("demo_SecureDelivery.zip");
        let manifest = SecureDeliveryManifestV1 {
            schema_version: 1,
            package_format: PackageFormat::SecureDeliveryZip,
            created_utc: "2026-01-01T00:00:00Z".to_string(),
            package_name: "demo".to_string(),
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
            },
        };
        write_delivery_zip(&out_zip, &payload, &manifest, None).expect("package write");
        let payload_bytes = read_payload_bytes(&out_zip).expect("read payload");
        let plain_bundle = decrypt_payload_bytes(&payload_bytes, b"1234567890").expect("decrypt payload");
        let extracted = td.path().join("extracted");
        extract_plain_bundle_zip(&plain_bundle, &extracted).expect("extract");

        let extracted_file = extracted.join("src").join("note.txt");
        let actual = fs::read_to_string(extracted_file).expect("read extracted");
        assert_eq!(actual, "secure delivery data");
    }
}
