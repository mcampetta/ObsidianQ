use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObsidianError {
    // --- Format errors ---
    #[error("invalid magic bytes: expected 'OBSQ'")]
    InvalidMagic,

    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u8),

    #[error("unsupported cipher suite: {0:#04x}")]
    UnsupportedSuite(u8),

    #[error("unsupported mode: {0:#04x}")]
    UnsupportedMode(u8),

    #[error("header MAC verification failed")]
    HeaderMacFailure,

    #[error("chunk {index} AEAD authentication failed")]
    ChunkAuthFailure { index: u64 },

    #[error("chunk index mismatch: expected {expected}, got {got}")]
    ChunkIndexMismatch { expected: u64, got: u64 },

    #[error("footer MAC verification failed")]
    FooterMacFailure,

    #[error("truncated header: needed {needed} bytes, got {got}")]
    TruncatedHeader { needed: usize, got: usize },

    // --- Crypto errors ---
    #[error("KEM encapsulation failed")]
    KemEncapFailure,

    #[error("KEM decapsulation failed")]
    KemDecapFailure,

    #[error("key derivation error")]
    KdfError,

    #[error("AEAD encryption error")]
    AeadEncryptError,

    #[error("AEAD decryption error")]
    AeadDecryptError,

    // --- KEM key parse errors ---
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    // --- IO ---
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // --- Compression ---
    #[error("compression error: {0}")]
    CompressionError(String),

    #[error("decompression error: {0}")]
    DecompressionError(String),

    // --- Password ---
    #[error("password hashing error")]
    PasswordHashError,
}

pub type Result<T> = std::result::Result<T, ObsidianError>;
