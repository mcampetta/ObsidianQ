# Secure Connect v1

Secure Connect is a relay-based, end-to-end encrypted pairing flow for non-technical users.

## UX summary

1. `Receive Connection`:
   - Create session (`session_id`, 9-digit code, ephemeral PQC keypair).
   - Register on relay.
   - Show code + QR payload `{ relay_url, code }`.
2. `Send Connection`:
   - Enter code.
   - Join relay session and fetch receiver ephemeral public key.
   - Encapsulate to receiver key, forward KEM ciphertext via relay.
3. Both derive session key and verification phrase.
4. User confirms phrase (`They Match`).
5. Encrypted text messages can be exchanged via relay.

## Cryptography

- KEM: existing ObsidianQ KEM primitives (Kyber768 implementation in `obsidianq-core`).
- Session key: `HKDF-SHA256(shared_secret, salt=session_id, info="obsidianq-secure-connect-v1")`.
- Verification phrase:
  - `HKDF-SHA256(session_key, salt=session_id, info="obsidianq-secure-connect-v1-verify")`
  - first 3 bytes map into a built-in 256-word list (`word-word-word`).
- Message AEAD:
  - `AES-256-GCM`
  - nonce = `direction_prefix(4 bytes) || counter(8 bytes)`
  - AAD = `session_id` bytes
  - Replay guard: monotonic receive counter.

## Relay messages

Client -> relay:

- `receive_start { code, session_id, public_key }`
- `send_join { code }`
- `relay { payload }` (opaque to relay)

Relay -> client:

- `receive_ready`
- `session_info { session_id, public_key }`
- `peer_connected`
- `relay { payload }`
- `error { message }`

## Relay properties

- In-memory sessions keyed by pairing code.
- Forwards opaque payload strings only.
- Session TTL cleanup after idle timeout.
