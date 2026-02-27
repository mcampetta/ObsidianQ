//! ObsidianQ core library.
//!
//! Public API surface:
//!   - `engine::encrypt` / `engine::decrypt`  — main file pipeline
//!   - `crypto::kem`     — ML-KEM-768 key generation, encap, decap
//!   - `crypto::kdf`     — HKDF root + chunk key derivation, Argon2id
//!   - `format`          — binary format types (FileHeader, ChunkRecord, …)
//!   - `error`           — ObsidianError + Result alias

pub mod crypto;
pub mod engine;
pub mod error;
pub mod format;

// Re-export the most-used items for convenience.
pub use engine::{decrypt, encrypt, open_container, hash_header, EncryptParams, ContainerManifest, ChunkRef, DEFAULT_CHUNK_SIZE};
pub use error::{ObsidianError, Result};
pub use format::{Mode, SuiteId};
