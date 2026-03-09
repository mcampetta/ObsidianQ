# ObsidianQ Exchange v1

This document defines the initial `obsidianq exchange` packet flow.

## Goal

Enable two users to transfer encrypted data using PQC KEM keys and ObsidianQ AEAD suites via portable packet files (`.obsqx`).

## Packet

Binary packet layout:

1. `magic[8] = "OBSQX1\0\0"`
2. `version: u16 = 1`
3. `suite_id: u8` (`0=xchacha20`, `1=aesgcm`)
4. `reserved: u8 = 0`
5. `filename_len: u16`
6. `filename_utf8[filename_len]`
7. `file_id[16]` (nonce domain)
8. `kem_ct[1088]` (Kyber768 ciphertext)
9. `payload_ct_len: u64`
10. `payload_ct[payload_ct_len]` (AEAD ciphertext+tag)

## Key agreement and encryption

Sender:

1. Load recipient public key.
2. KEM encapsulate -> `(kem_ct, ss)`.
3. Derive root key via HKDF (`obsidianq-exchange-v1-salt`).
4. Derive data key from root key (`chunk_index=0`, fixed header hash for v1).
5. Encrypt payload as one chunk with chosen suite.

Receiver:

1. Load recipient private key.
2. KEM decapsulate with `kem_ct` -> `ss`.
3. Derive same root/data key.
4. Decrypt payload and write output.

## CLI commands

1. `obsidianq exchange send --in <file> --out <packet.obsqx> --pubkey <pub.bin|pub.pem> [--suite xchacha20|aesgcm]`
2. `obsidianq exchange recv --in <packet.obsqx> --privkey <priv.bin|priv.pem> --out-dir <dir>`
3. `obsidianq exchange fingerprint --key <pub|priv>`

## Notes

1. v1 is file-based packet exchange, not live networking.
2. v1 currently encrypts one payload blob per packet (no chunk stream protocol yet).
3. Replay protection and contact/session state are planned for v2.
