use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use base64ct::{Base64, Encoding};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use crate::{
    crypto::kem::{self, CT_BYTES, DK_BYTES, EK_BYTES, SS_BYTES},
    error::{ObsidianError, Result},
};

const INFO_SESSION_KEY: &[u8] = b"obsidianq-secure-connect-v1";
const INFO_VERIFY: &[u8] = b"obsidianq-secure-connect-v1-verify";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s).map_err(|_| ObsidianError::InvalidPublicKey("session_id".into()))?;
        if raw.len() != 16 {
            return Err(ObsidianError::InvalidPublicKey("session_id_length".into()));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&raw);
        Ok(Self(out))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

pub fn generate_pairing_code() -> String {
    let mut raw = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut raw);
    let value = u32::from_le_bytes(raw) % 1_000_000_000;
    let code = format!("{value:09}");
    format!("{}-{}-{}", &code[0..3], &code[3..6], &code[6..9])
}

pub fn generate_ephemeral_keypair_b64() -> (String, String) {
    let (ek, dk) = kem::generate_keypair();
    (
        Base64::encode_string(&ek.0),
        Base64::encode_string(&dk.0),
    )
}

pub fn encapsulate_to_peer_b64(peer_pub_b64: &str) -> Result<(String, [u8; SS_BYTES])> {
    let peer_raw =
        Base64::decode_vec(peer_pub_b64).map_err(|_| ObsidianError::InvalidPublicKey("base64".into()))?;
    if peer_raw.len() != EK_BYTES {
        return Err(ObsidianError::InvalidPublicKey("length".into()));
    }
    let mut peer = [0u8; EK_BYTES];
    peer.copy_from_slice(&peer_raw);
    let (ct, ss) = kem::encapsulate(&peer)?;
    Ok((Base64::encode_string(&ct), *ss.as_bytes()))
}

pub fn decapsulate_b64(private_b64: &str, ct_b64: &str) -> Result<[u8; SS_BYTES]> {
    let dk_raw =
        Base64::decode_vec(private_b64).map_err(|_| ObsidianError::InvalidPrivateKey("base64".into()))?;
    if dk_raw.len() != DK_BYTES {
        return Err(ObsidianError::InvalidPrivateKey("length".into()));
    }
    let ct_raw = Base64::decode_vec(ct_b64).map_err(|_| ObsidianError::KemDecapFailure)?;
    if ct_raw.len() != CT_BYTES {
        return Err(ObsidianError::KemDecapFailure);
    }

    let mut dk = [0u8; DK_BYTES];
    dk.copy_from_slice(&dk_raw);
    let mut ct = [0u8; CT_BYTES];
    ct.copy_from_slice(&ct_raw);
    let ss = kem::decapsulate(&dk, &ct)?;
    Ok(*ss.as_bytes())
}

pub fn derive_session_key(shared_secret: &[u8; SS_BYTES], session_id: &SessionId) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(INFO_SESSION_KEY, &mut key)
        .map_err(|_| ObsidianError::KdfError)?;
    Ok(key)
}

pub fn compute_verify_phrase(session_key: &[u8; 32], session_id: &SessionId) -> Result<String> {
    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), session_key);
    let mut out = [0u8; 3];
    hk.expand(INFO_VERIFY, &mut out)
        .map_err(|_| ObsidianError::KdfError)?;
    Ok(format!(
        "{}-{}-{}",
        WORDS[out[0] as usize], WORDS[out[1] as usize], WORDS[out[2] as usize]
    ))
}

pub fn encrypt_message(
    session_key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(session_key.into());
    cipher
        .encrypt(nonce.into(), aes_gcm::aead::Payload { msg: plaintext, aad })
        .map_err(|_| ObsidianError::AeadEncryptError)
}

pub fn decrypt_message(
    session_key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(session_key.into());
    cipher
        .decrypt(nonce.into(), aes_gcm::aead::Payload { msg: ciphertext, aad })
        .map_err(|_| ObsidianError::AeadDecryptError)
}

// 256 short words for human verification phrases.
const WORDS: [&str; 256] = [
    "amber","apple","arrow","atlas","azure","baker","beacon","birch","blade","blaze","bloom","bravo","brook","cable","cactus","candle",
    "canyon","carbon","cedar","charm","cipher","clover","cobalt","comet","coral","cosmos","crane","crest","crystal","delta","dingo","drift",
    "eagle","echo","ember","falcon","fable","fjord","flora","flux","forest","frost","gamma","garden","glade","glint","globe","granite",
    "harbor","hazel","helix","hollow","horizon","hunter","indigo","iris","island","ivory","jaguar","jasmine","jewel","journey","juniper","kettle",
    "king","kiwi","lagoon","laser","laurel","legend","lemon","lily","lunar","maple","matrix","meadow","mercury","meteor","mimic","mint",
    "mirage","moss","nebula","nectar","needle","nimbus","nova","oak","oasis","onyx","opal","orbit","otter","panda","pearl","phoenix",
    "pioneer","pixel","plasma","polar","prairie","prism","python","quartz","quest","raven","reef","relay","ridge","river","rocket","ruby",
    "saffron","sailor","sakura","saturn","scarlet","scout","shadow","silver","sky","solace","sonic","spark","spectrum","spirit","spruce","static",
    "stone","storm","sunset","swift","tango","teal","temple","terra","thunder","tiger","topaz","torch","trident","tulip","turbo","ultra",
    "umber","unison","valley","vapor","velvet","vertex","violet","vision","voyage","walnut","wave","whisper","willow","wind","winter","xenon",
    "yarrow","yellow","yonder","zephyr","zinc","zodiac","alpha","beta","charlie","dragon","elm","ferry","grove","haven","ion","jet",
    "koala","linen","marble","north","olive","pebble","quill","ripple","sage","timber","unity","vector","wren","yeti","zenith","anchor",
    "breeze","cinder","dawn","emberly","feather","glacier","harvest","icicle","jungle","kernel","lantern","meadowlark","night","orchid","poppy","quiver",
    "raindrop","signal","traveler","uplift","verge","wild","yearling","zen","acorn","basil","copper","dolphin","elmwood","futura","galaxy","harpoon",
    "ink","jade","krypton","lotus","mango","nickel","origin","petal","quasar","radar","sierra","tempo","utopia","velour","wander","yukon",
    "apex","banner","cobalt2","drum","ember2","flint","gale","harvest2","iris2","jolt","keystone","lumen","morrow","noble","oxide","pulse",
];
