use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{ObsidianError, Result};

pub const HYBRID_RECIPIENT_MAGIC_V1: &[u8; 4] = b"MRK3";
pub const X25519_PUBLIC_BYTES: usize = 32;
pub const X25519_PRIVATE_BYTES: usize = 32;
pub const HYBRID_KEY_BYTES: usize = 32;

const INFO_HYBRID_WRAP: &[u8] = b"obsidianq-v1-hybrid-wrap";

pub fn generate_x25519_keypair() -> ([u8; X25519_PUBLIC_BYTES], [u8; X25519_PRIVATE_BYTES]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (public.to_bytes(), secret.to_bytes())
}

pub fn encapsulate_x25519(
    recipient_public: &[u8; X25519_PUBLIC_BYTES],
) -> ([u8; X25519_PUBLIC_BYTES], [u8; HYBRID_KEY_BYTES]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&secret).to_bytes();
    let recipient_public = PublicKey::from(*recipient_public);
    let shared = secret.diffie_hellman(&recipient_public).to_bytes();
    (ephemeral_public, shared)
}

pub fn decapsulate_x25519(
    recipient_private: &[u8; X25519_PRIVATE_BYTES],
    ephemeral_public: &[u8; X25519_PUBLIC_BYTES],
) -> [u8; HYBRID_KEY_BYTES] {
    let secret = StaticSecret::from(*recipient_private);
    let public = PublicKey::from(*ephemeral_public);
    secret.diffie_hellman(&public).to_bytes()
}

pub fn derive_hybrid_wrap_key(
    kyber_shared: &[u8; HYBRID_KEY_BYTES],
    x25519_shared: &[u8; HYBRID_KEY_BYTES],
    salt: &[u8],
) -> Result<[u8; HYBRID_KEY_BYTES]> {
    let mut ikm = [0u8; HYBRID_KEY_BYTES * 2];
    ikm[..HYBRID_KEY_BYTES].copy_from_slice(kyber_shared);
    ikm[HYBRID_KEY_BYTES..].copy_from_slice(x25519_shared);

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; HYBRID_KEY_BYTES];
    hk.expand(INFO_HYBRID_WRAP, &mut okm)
        .map_err(|_| ObsidianError::KdfError)?;
    Ok(okm)
}
