# Security Architecture

This document gives a reviewer-friendly overview of the current ObsidianQ security model without claiming more than the implementation supports today.

## Core Building Blocks

- Password mode uses Argon2id-derived key material
- Content encryption uses XChaCha20-Poly1305
- Hashing and fingerprints use BLAKE3
- Current trusted-contact recipient exchange uses Kyber Round 3 via `pqcrypto-kyber`

Important wording note:

- Current recipient exchange is not claimed to be FIPS 203 ML-KEM compliant
- Interoperability with standardized ML-KEM implementations should not be assumed

## Local-First Model

- Encryption and decryption run locally
- Private keys remain under user control
- Public identities are exchanged directly between users
- Core file and package workflows do not require a cloud key server

## Package Verification

Secure Delivery packages can include:

- package metadata
- a manifest describing expected contents
- optional signing identity metadata
- optional signature-based verification data

Verification helps detect:

- tampering
- manifest mismatch
- missing signing identity
- unsigned packages

Verification status is informational unless a consuming workflow explicitly treats failures as blocking.

## Delivery Modes

- Password mode remains the broadest compatibility option
- Trusted-contact recipient exchange is intended for known-recipient workflows
- Self-extracting EXE delivery is a compatibility mode and may be treated as suspicious by email and endpoint tools

For email and customer-facing distribution, ZIP-based delivery bundles are generally safer operationally than raw executable attachments.
