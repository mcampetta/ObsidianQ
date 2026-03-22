# ObsidianQ Format Notes

This document describes the current on-disk and delivery-container formats at a reviewer-friendly level. It is intentionally high level and does not claim more precision than the code currently guarantees.

## File Extensions

- `.obsq`
  Encrypted file container used for password mode and recipient-based encryption.
- `.vault`
  Native vault container format used by the vault workflows.
- `.obsqv`
  Vault-style or mounted-container related file handled by launcher inspect/open flows.
- `.obsqpub`
  Public identity document for exchanging recipient metadata and public key material.
- `*_SecureDelivery.zip`
  Secure Delivery package or ZIP delivery bundle, depending on contents.
- `*_SecureDelivery.exe`
  Single-file Secure Delivery executable package.

## Versioning Strategy

- `.obsq` files carry a binary header version.
- Current `.obsq` version in code is `0x02`.
- Secure Delivery manifests carry a JSON `schema_version`.
- New recipient slot layouts are distinguished by slot magic values inside `kem_data`, so legacy recipient files remain readable alongside newer hybrid files.

## `.obsq` High-Level Structure

An `.obsq` file contains:

1. Header
2. Chunked encrypted body
3. Footer

The header includes:

- magic
- version
- access mode
- cipher suite
- flags
- chunk size
- file ID
- `kem_data`
- header MAC

The body is chunked and authenticated per chunk.

The footer includes:

- chunk count
- global MAC over chunk-tag material

## Manifest / Integrity Role

For `.obsq`, integrity is enforced by the authenticated header, per-chunk AEAD, and footer MAC.

For Secure Delivery packages, the manifest is a JSON description of:

- package metadata
- payload hash
- file list
- optional sender identity metadata
- optional manifest signature

Verification is based on:

- manifest integrity
- payload hash match
- optional signature validation
- optional sender identity presence

## Recipient Slots in `.obsq`

Password mode:

- `kem_data` stores a 32-byte Argon2id salt

Legacy recipient mode:

- single-recipient legacy layout stores Kyber Round 3 ciphertext plus HKDF salt
- multi-recipient legacy layouts use `MRK1` or `MRK2`

Hybrid recipient mode:

- multi-recipient hybrid layout uses `MRK3`
- each recipient entry includes:
  - Kyber Round 3 ciphertext
  - ephemeral X25519 public key
  - wrapped master-key material
- the final wrapping key is derived from both the Kyber and X25519 shared secrets through HKDF

Current inspect labels should be read as:

- `Password`
- `Hybrid Contact`
- `Multi-Recipient Hybrid`
- `Legacy Contact`

## Secure Delivery Package Structure

A raw Secure Delivery package ZIP contains:

- `secure_delivery_manifest.json`
- `payload.obsq`
- optional `instructions.txt`
- optional sender/signature metadata referenced by the manifest

The encrypted payload is password-based today.

## ZIP Delivery Bundle Structure

The launcher's safer ZIP delivery output is an outer ZIP bundle that contains:

- `decrypt.html`
- `package.zip`
- `README.txt`

This is distinct from the raw Secure Delivery package ZIP. The outer bundle exists to make recipient handling easier without attaching a standalone executable directly.

The bundled `decrypt.html` is a self-contained offline copy of the browser decryptor:

- no remote scripts, styles, or APIs
- decryption remains client-side
- recipients can disconnect from the internet before opening it

## Single EXE Delivery Structure

A single EXE delivery package contains:

- bootstrapper host executable
- embedded Secure Delivery package ZIP
- embedded `obsidianq.exe`
- a trailer containing payload lengths and magic

## Backwards Compatibility Notes

- Password-mode `.obsq` remains unchanged.
- Legacy recipient-encrypted `.obsq` files remain supported.
- New hybrid recipient files are distinguishable from legacy files by recipient-slot layout.
- Secure Delivery inspect/extract workflows should handle:
  - raw package ZIPs
  - ZIP delivery bundles
  - single EXE packages

## Non-Claims

- This document does not claim formal audit status.
- It does not claim FIPS 203 ML-KEM compliance.
- It does not claim interoperability with standardized ML-KEM implementations.
