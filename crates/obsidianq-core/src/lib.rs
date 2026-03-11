//! ObsidianQ core library.
//!
//! Public API surface:
//!   - `engine::encrypt` / `engine::decrypt`  — main file pipeline
//!   - `crypto::kem`     — ML-KEM-768 key generation, encap, decap
//!   - `crypto::kdf`     — HKDF root + chunk key derivation, Argon2id
//!   - `format`          — binary format types (FileHeader, ChunkRecord, …)
//!   - `error`           — ObsidianError + Result alias

pub mod crypto;
pub mod delivery;
pub mod engine;
pub mod error;
pub mod format;
pub mod secure_connect;

// Re-export the most-used items for convenience.
pub use engine::{
    decrypt, encrypt, hash_header, open_container, ChunkRef, ContainerManifest, EncryptParams,
    DEFAULT_CHUNK_SIZE,
};
pub use error::{ObsidianError, Result};
pub use format::{Mode, SuiteId};
