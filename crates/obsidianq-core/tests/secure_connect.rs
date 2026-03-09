use obsidianq_core::{
    crypto::kem,
    secure_connect::{
        compute_verify_phrase, decrypt_message, derive_session_key, encrypt_message, SessionId,
    },
};

#[test]
fn handshake_success_and_phrase_matches() {
    let (ek_a, dk_a) = kem::generate_keypair();
    let (ct, ss_b) = kem::encapsulate(&ek_a.0).expect("encapsulate");
    let ss_a = kem::decapsulate(&dk_a.0, &ct).expect("decapsulate");
    assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());

    let sid = SessionId::random();
    let key_a = derive_session_key(ss_a.as_bytes(), &sid).expect("derive A");
    let key_b = derive_session_key(ss_b.as_bytes(), &sid).expect("derive B");
    assert_eq!(key_a, key_b);

    let phrase_a = compute_verify_phrase(&key_a, &sid).expect("phrase A");
    let phrase_b = compute_verify_phrase(&key_b, &sid).expect("phrase B");
    assert_eq!(phrase_a, phrase_b);
}

#[test]
fn aead_round_trip() {
    let sid = SessionId::random();
    let shared = [7u8; 32];
    let key = derive_session_key(&shared, &sid).expect("derive");
    let nonce = [1u8; 12];
    let aad = sid.as_bytes();
    let pt = b"secure connect payload";
    let ct = encrypt_message(&key, &nonce, pt, aad).expect("encrypt");
    let dec = decrypt_message(&key, &nonce, &ct, aad).expect("decrypt");
    assert_eq!(dec, pt);
}

#[test]
fn handshake_success_with_mock_relay_forward() {
    // Mock relay forwards B's KEM ciphertext payload to A.
    let (ek_a, dk_a) = kem::generate_keypair();
    let (ct_from_b, ss_b) = kem::encapsulate(&ek_a.0).expect("encapsulate");
    let forwarded_ct = ct_from_b; // relay cannot decrypt; just forwards bytes.
    let ss_a = kem::decapsulate(&dk_a.0, &forwarded_ct).expect("decapsulate");
    assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());

    let sid = SessionId::random();
    let key_a = derive_session_key(ss_a.as_bytes(), &sid).expect("derive A");
    let key_b = derive_session_key(ss_b.as_bytes(), &sid).expect("derive B");
    assert_eq!(key_a, key_b);
}
