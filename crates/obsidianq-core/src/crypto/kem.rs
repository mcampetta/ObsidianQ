//! Kyber768 key encapsulation wrappers.
//!
//! Uses `pqcrypto-kyber` 0.8 which implements **Kyber768 (NIST Round 3
//! submission)**, NOT FIPS 203 ML-KEM-768.  The two are based on the same
//! lattice problem and have equivalent security levels, but they are
//! **not wire-compatible**: ciphertexts produced here cannot be decapsulated
//! by a FIPS 203 implementation and vice-versa.  When a stable
//! `ml-kem` crate resolves its pre-release dependency issues, migrate to that
//! for genuine FIPS 203 compliance.
//!
//! Key sizes (Kyber768):
//!   PublicKey  (EK)  : 1184 bytes
//!   SecretKey  (DK)  : 2400 bytes
//!   Ciphertext (CT)  : 1088 bytes
//!   SharedSecret     :   32 bytes

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{ObsidianError, Result};

pub const EK_BYTES: usize = 1184;
pub const DK_BYTES: usize = 2400;
pub const CT_BYTES: usize = 1088;
pub const SS_BYTES: usize = 32;

/// A 32-byte shared secret — zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub(crate) [u8; SS_BYTES]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; SS_BYTES] {
        &self.0
    }
}

/// Raw public (encapsulation) key bytes.
pub struct EncapKeyBytes(pub [u8; EK_BYTES]);

/// Raw secret (decapsulation) key bytes — zeroized on drop.
pub struct DecapKeyBytes(pub [u8; DK_BYTES]);

impl Zeroize for DecapKeyBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for DecapKeyBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Generate a fresh Kyber768 keypair.
pub fn generate_keypair() -> (EncapKeyBytes, DecapKeyBytes) {
    let (pk, sk) = kyber768::keypair();

    let pk_bytes = pk.as_bytes();
    let mut ek = [0u8; EK_BYTES];
    ek.copy_from_slice(pk_bytes);

    let sk_bytes = sk.as_bytes();
    let mut dk = [0u8; DK_BYTES];
    dk.copy_from_slice(sk_bytes);

    (EncapKeyBytes(ek), DecapKeyBytes(dk))
}

/// Encapsulate: produce a (ciphertext[1088], shared_secret[32]) pair
/// bound to the recipient's public key.
pub fn encapsulate(ek_bytes: &[u8; EK_BYTES]) -> Result<([u8; CT_BYTES], SharedSecret)> {
    let pk = kyber768::PublicKey::from_bytes(ek_bytes)
        .map_err(|e| ObsidianError::InvalidPublicKey(e.to_string()))?;

    let (ss, ct) = kyber768::encapsulate(&pk);

    let mut ct_out = [0u8; CT_BYTES];
    ct_out.copy_from_slice(ct.as_bytes());

    let mut ss_out = [0u8; SS_BYTES];
    ss_out.copy_from_slice(ss.as_bytes());

    Ok((ct_out, SharedSecret(ss_out)))
}

/// Decapsulate: recover the shared secret from a ciphertext using the private key.
pub fn decapsulate(dk_bytes: &[u8; DK_BYTES], ct_bytes: &[u8; CT_BYTES]) -> Result<SharedSecret> {
    let sk = kyber768::SecretKey::from_bytes(dk_bytes)
        .map_err(|e| ObsidianError::InvalidPrivateKey(e.to_string()))?;
    let ct =
        kyber768::Ciphertext::from_bytes(ct_bytes).map_err(|_| ObsidianError::KemDecapFailure)?;

    let ss = kyber768::decapsulate(&ct, &sk);

    let mut ss_out = [0u8; SS_BYTES];
    ss_out.copy_from_slice(ss.as_bytes());

    Ok(SharedSecret(ss_out))
}
