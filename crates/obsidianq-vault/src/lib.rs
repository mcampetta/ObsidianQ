//! ObsidianQ native vault format (`.vault`) — read/write encrypted directory tree.
//!
//! # Architecture
//! - [`format`]    — on-disk binary layout: ImmutableHeader, Superblock, DirBlock, DirEntry
//! - [`bat`]       — BlockAllocationTable (in-memory bit array, flushed on commit)
//! - [`crypto`]    — per-block encrypt/decrypt wrappers (reuses obsidianq-core)
//! - [`dir`]       — directory tree operations (path resolution, entry CRUD)
//! - [`container`] — VaultContainer (public API: create/open/flush + FS ops + I/O)

pub mod bat;
pub mod container;
pub mod crypto;
pub mod dir;
pub mod format;

pub use container::{CreateParams, VaultContainer, VaultFileHandle};

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// Metadata snapshot returned by stat / list_dir.
#[derive(Debug, Clone)]
pub struct EntryInfo {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub attr: u8,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("invalid magic bytes (not an ObsidianQ vault)")]
    InvalidMagic,

    #[error("unsupported vault version: {0:#04x}")]
    UnsupportedVersion(u8),

    #[error("invalid mode byte")]
    InvalidMode,

    #[error("invalid suite byte")]
    InvalidSuite,

    #[error("immutable header MAC mismatch — wrong key or corrupted header")]
    HeaderMacMismatch,

    #[error("superblock MAC mismatch")]
    SuperblockMacMismatch,

    #[error("no valid superblock found (vault may be corrupted)")]
    NoValidSuperblock,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("already exists: {0}")]
    AlreadyExists(String),

    #[error("not a directory: {0}")]
    NotADirectory(String),

    #[error("is a directory: {0}")]
    IsADirectory(String),

    #[error("directory not empty: {0}")]
    DirectoryNotEmpty(String),

    #[error("vault is full (BAT capacity exceeded ~32 GiB)")]
    OutOfSpace,

    #[error("file too large for single-level index (max ~511 MiB per file)")]
    FileTooLarge,

    #[error("format error: {0}")]
    FormatError(String),

    #[error("crypto error: {0}")]
    CryptoError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use container::CreateParams;
    use obsidianq_core::{
        crypto::kdf::{self, Argon2Params, MasterKey},
        format::{Mode, SuiteId},
    };

    fn make_key() -> MasterKey {
        kdf::derive_password_key(b"testpassword", &[0u8; 32], &Argon2Params::default()).unwrap()
    }

    fn make_params() -> (MasterKey, CreateParams) {
        let key = make_key();
        let params = CreateParams {
            master_key: make_key(), // second derivation for params
            kem_data: vec![0u8; 32],
            mode: Mode::Password,
            suite: SuiteId::XChaCha20Poly1305,
            file_id: [0x42u8; 16],
            block_size: 65536,
            initial_blocks: 0,
        };
        (key, params)
    }

    #[test]
    fn test_create_open_list_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let (key, params) = make_params();
        {
            let _vc = VaultContainer::create(&path, params).unwrap();
        }
        let mut vc = VaultContainer::open(&path, key).unwrap();
        let entries = vc.list_dir("/").unwrap();
        assert!(
            entries.is_empty(),
            "fresh vault should have no entries, got: {:?}",
            entries
        );
    }

    #[test]
    fn test_create_add_file_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let src = dir.path().join("hello.txt");
        std::fs::write(&src, b"Hello, ObsidianQ!").unwrap();

        let (_key_unused, params) = make_params();
        {
            let mut vc = VaultContainer::create(&path, params).unwrap();
            vc.import_file(&src, "/hello.txt").unwrap();
            vc.flush().unwrap();
        }

        // Re-open with a freshly derived key (same password/salt).
        let mut vc2 = VaultContainer::open(&path, make_key()).unwrap();
        let entries = vc2.list_dir("/").unwrap();
        assert_eq!(
            entries.len(),
            1,
            "expected 1 entry after import, got {:?}",
            entries
        );
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].size, 17);
    }

    #[test]
    fn test_round_trip_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let content = b"The quick brown fox jumps over the lazy dog. ".repeat(2000);

        let (_k, params) = make_params();
        {
            let mut vc = VaultContainer::create(&path, params).unwrap();
            let src = dir.path().join("big.bin");
            std::fs::write(&src, &content).unwrap();
            vc.import_file(&src, "/big.bin").unwrap();
            vc.flush().unwrap();
        }

        let mut vc2 = VaultContainer::open(&path, make_key()).unwrap();
        let dest = dir.path().join("out.bin");
        vc2.export_file("/big.bin", &dest).unwrap();
        let got = std::fs::read(&dest).unwrap();
        assert_eq!(got, content);
    }
}
