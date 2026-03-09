//! Binary file format for ObsidianQ (.obsq)
//!
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  HEADER                                                         │
//! │  Magic        4 bytes  "OBSQ"                                   │
//! │  Version      1 byte   0x01                                     │
//! │  Mode         1 byte   0=Password, 1=PQC                        │
//! │  Suite ID     1 byte   0=XChaCha20-Poly1305, 1=AES-256-GCM     │
//! │  Flags        1 byte   bit0=compressed                          │
//! │  Chunk size   4 bytes  LE u32 (in bytes, default 1 MiB)        │
//! │  File ID      16 bytes random, used in nonce derivation         │
//! │  KEM data len 2 bytes  LE u16 (salt=32B for pwd, ct≈1088B pqc) │
//! │  KEM data     variable (salt or ML-KEM ciphertext)             │
//! │  Header MAC   32 bytes BLAKE3 keyed MAC over above bytes        │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  BODY  (N chunks, indices 0..N-1)                               │
//! │  ┌──────────────────────────────────────────────────────────┐   │
//! │  │ Chunk index   8 bytes  LE u64                            │   │
//! │  │ CT length     4 bytes  LE u32 (includes 16-byte tag)    │   │
//! │  │ Ciphertext    CT length bytes                            │   │
//! │  └──────────────────────────────────────────────────────────┘   │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  FOOTER                                                         │
//! │  Chunk count  8 bytes  LE u64                                   │
//! │  Global MAC   32 bytes BLAKE3 MAC over all chunk tags           │
//! └─────────────────────────────────────────────────────────────────┘

use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io::{Read, Write};

use crate::error::{ObsidianError, Result};

pub const MAGIC: &[u8; 4] = b"OBSQ";
/// Format version.  Increment whenever on-disk layout or crypto is altered.
/// v1 → v2: MAC domain separation, footer binds header_hash, suite-keyed nonces.
pub const VERSION: u8 = 0x02;

/// Cipher suite IDs — selectable per-file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SuiteId {
    XChaCha20Poly1305 = 0x00,
    Aes256Gcm = 0x01,
}

impl TryFrom<u8> for SuiteId {
    type Error = ObsidianError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(SuiteId::XChaCha20Poly1305),
            0x01 => Ok(SuiteId::Aes256Gcm),
            other => Err(ObsidianError::UnsupportedSuite(other)),
        }
    }
}

/// Operational mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Password = 0x00,
    Pqc = 0x01,
}

impl TryFrom<u8> for Mode {
    type Error = ObsidianError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(Mode::Password),
            0x01 => Ok(Mode::Pqc),
            other => Err(ObsidianError::UnsupportedMode(other)),
        }
    }
}

/// Flags bitfield.
pub mod flags {
    pub const COMPRESSED: u8 = 0b0000_0001;
}

/// Parsed file header.  KEM data is:
///  - Password mode : 32-byte Argon2id salt
///  - PQC mode      : ML-KEM-768 ciphertext (1088 bytes) ++ 32-byte HKDF salt
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub version: u8,
    pub mode: Mode,
    pub suite: SuiteId,
    pub flags: u8,
    /// Chunk size in bytes (must be a power of two, ≥ 4096).
    pub chunk_size: u32,
    /// Random 16-byte file ID used in nonce derivation.
    pub file_id: [u8; 16],
    /// Variable-length KEM data (salt or KEM ciphertext).
    pub kem_data: Vec<u8>,
    /// BLAKE3 keyed MAC over everything above this field.
    pub mac: [u8; 32],
}

impl FileHeader {
    /// Serialize the header (excluding mac) into `buf` for MAC computation.
    pub fn canonical_bytes_for_mac(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.kem_data.len());
        buf.extend_from_slice(MAGIC);
        buf.push(self.version);
        buf.push(self.mode as u8);
        buf.push(self.suite as u8);
        buf.push(self.flags);
        buf.extend_from_slice(&self.chunk_size.to_le_bytes());
        buf.extend_from_slice(&self.file_id);
        buf.extend_from_slice(&(self.kem_data.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.kem_data);
        buf
    }

    /// Write the full header (including MAC) to `writer`.
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(MAGIC)?;
        w.write_u8(self.version)?;
        w.write_u8(self.mode as u8)?;
        w.write_u8(self.suite as u8)?;
        w.write_u8(self.flags)?;
        w.write_u32::<LE>(self.chunk_size)?;
        w.write_all(&self.file_id)?;
        w.write_u16::<LE>(self.kem_data.len() as u16)?;
        w.write_all(&self.kem_data)?;
        w.write_all(&self.mac)?;
        Ok(())
    }

    /// Read and parse the header from `reader`.  Does NOT verify the MAC —
    /// that is done by the caller once the master key is known.
    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)
            .map_err(|_| ObsidianError::TruncatedHeader { needed: 4, got: 0 })?;
        if &magic != MAGIC {
            return Err(ObsidianError::InvalidMagic);
        }

        let version = r.read_u8()?;
        if version != VERSION {
            return Err(ObsidianError::UnsupportedVersion(version));
        }

        let mode = Mode::try_from(r.read_u8()?)?;
        let suite = SuiteId::try_from(r.read_u8()?)?;
        let flags = r.read_u8()?;
        let chunk_size = r.read_u32::<LE>()?;

        let mut file_id = [0u8; 16];
        r.read_exact(&mut file_id)?;

        let kem_len = r.read_u16::<LE>()? as usize;
        let mut kem_data = vec![0u8; kem_len];
        r.read_exact(&mut kem_data)?;

        let mut mac = [0u8; 32];
        r.read_exact(&mut mac)?;

        Ok(FileHeader {
            version,
            mode,
            suite,
            flags,
            chunk_size,
            file_id,
            kem_data,
            mac,
        })
    }
}

/// A single encrypted chunk record (body section).
pub struct ChunkRecord {
    pub index: u64,
    pub ciphertext: Vec<u8>, // already includes the 16-byte AEAD tag
}

impl ChunkRecord {
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_u64::<LE>(self.index)?;
        w.write_u32::<LE>(self.ciphertext.len() as u32)?;
        w.write_all(&self.ciphertext)?;
        Ok(())
    }

    pub fn read_from<R: Read>(r: &mut R) -> Result<Option<Self>> {
        // Read index — EOF here is normal (end of body).
        let index = match r.read_u64::<LE>() {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let ct_len = r.read_u32::<LE>()? as usize;
        let mut ciphertext = vec![0u8; ct_len];
        r.read_exact(&mut ciphertext)?;
        Ok(Some(ChunkRecord { index, ciphertext }))
    }
}

/// File footer.
pub struct FileFooter {
    pub chunk_count: u64,
    /// BLAKE3 keyed MAC over the concatenation of all chunk tags (last 16B of each ct).
    pub global_mac: [u8; 32],
}

impl FileFooter {
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_u64::<LE>(self.chunk_count)?;
        w.write_all(&self.global_mac)?;
        Ok(())
    }

    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let chunk_count = r.read_u64::<LE>()?;
        let mut global_mac = [0u8; 32];
        r.read_exact(&mut global_mac)?;
        Ok(FileFooter {
            chunk_count,
            global_mac,
        })
    }
}
