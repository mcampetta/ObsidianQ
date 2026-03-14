# ObsidianQ Security Architecture

## Overview

ObsidianQ is a local-first encryption platform designed for secure file protection, secure delivery packaging, trusted contact workflows, encrypted vaults, and package verification.

Its architecture is built around the following goals:

- strong confidentiality
- authenticated integrity
- practical performance
- simple delivery workflows
- support for both password-based and public-key-based protection
- future-friendly support for post-quantum key exchange

This document provides a high-level overview of the architecture and how the major pieces fit together.

---

## Design Principles

### 1. Local-First Encryption
Encryption and decryption are intended to happen on the user’s machine. The system is not built around a central key server or cloud decryption service.

### 2. Authenticated by Default
Encrypted data should not merely be unreadable to attackers; tampering should also be detectable.

### 3. Practical Usability
The system is designed not only as a cryptographic engine, but as a workflow tool with GUI, CLI, trusted contact exchange, package inspection, and secure delivery features.

### 4. Separation of Concerns
Core cryptographic operations are intended to remain centralized in the ObsidianQ core engine, while GUI and workflow layers orchestrate those operations rather than reimplementing them.

---

## Core Cryptographic Components

ObsidianQ currently uses modern primitives in the following general roles:

### Authenticated Encryption
**XChaCha20-Poly1305**

Used for payload confidentiality and integrity. This provides authenticated encryption with associated data and is well suited to chunked file processing.

### Password Hardening
**Argon2id**

Used when deriving encryption keys from user-supplied passwords. This helps resist brute force attacks by increasing attacker cost.

### Key Derivation / Key Separation
**HKDF-SHA256** or equivalent structured derivation

Used to derive subkeys and separate cryptographic roles such as payload encryption, manifest binding, and package integrity logic.

### Hashing / Fingerprinting
**BLAKE3**

Used for hashing, fingerprints, fast verification-oriented operations, and content identification.

### Public-Key Encryption / Post-Quantum Support
**ML-KEM / Kyber-family key encapsulation**

Used for trusted contact workflows and recipient-based encryption where configured.

---

## Architectural Layers

### 1. Core Encryption Engine
The core engine is responsible for:

- file encryption and decryption
- text encryption and decryption
- package encryption
- chunked processing
- manifest binding
- verification logic
- password and recipient workflows

This layer is security-critical.

### 2. Packaging / Container Layer
This layer defines how encrypted data is assembled into:

- `.obsq` encrypted packages
- `.obsqv` vault containers
- secure delivery containers
- signed package manifests
- self-extracting package variants

### 3. Identity / Contact Layer
This layer handles:

- local identity metadata
- public identity export/import
- secure contacts
- fingerprints
- recipient selection
- metadata-assisted key exchange

### 4. Application Layer
This includes:

- GUI tabs and workflows
- CLI commands
- viewer/extractor tools
- web decryptor integrations where applicable
- secure delivery package generation

---

## Data Protection Model

### Password-Based Protection
When a user chooses password-based encryption:

1. a user password is collected
2. Argon2id derives hardened key material
3. subkeys are derived for appropriate cryptographic functions
4. encrypted chunks are produced using authenticated encryption
5. package metadata is verified before extraction

### Public-Key-Based Protection
When a user encrypts for a trusted contact:

1. recipient public identity is selected
2. recipient public key is used in a key encapsulation step
3. package encryption keys are protected for that recipient
4. only the holder of the matching private key can decrypt the payload

### Multi-Recipient Protection
Where supported, a package can include multiple recipient protections so that any authorized recipient can decrypt the same encrypted payload.

---

## Chunked Encryption Model

Large files and payloads are processed in authenticated chunks.

Benefits include:

- improved performance on large files
- reduced memory pressure
- safer large-file handling
- clearer integrity boundaries
- support for verification and streaming workflows

Each encrypted chunk is intended to be bound into the package integrity model so that corruption, truncation, reordering, or tampering is detected.

---

## Package Manifest Model

Secure delivery packages include a manifest describing package contents and metadata.

Typical manifest information may include:

- package format version
- package ID
- sender identity information
- creation timestamp
- file list
- file sizes
- file hashes
- recipient mode
- tool version

The manifest is intended to make packages:

- inspectable
- verifiable
- tamper-evident
- audit-friendly

---

## Signature Model

Where package signing is enabled, the sender signs the package manifest.

This supports:

- sender authenticity
- tamper detection
- independent package verification
- audit and evidentiary workflows

Verification should occur before extraction when applicable.

---

## Secure Delivery Architecture

Secure Delivery packages are intended to support real-world encrypted distribution.

The packaging model supports:

- encrypted payload
- manifest
- sender metadata
- package ID
- optional self-extracting packaging
- optional lightweight viewer workflows

This allows senders to produce a single package for recipients who may not otherwise have the full application installed.

---

## Public Identity Model

ObsidianQ public identities wrap a public key with optional metadata such as:

- name
- email
- device
- created timestamp
- algorithm
- fingerprint

These metadata fields are usability aids and should not be automatically trusted without fingerprint verification.

The fingerprint remains the critical identity handle.

---

## Verification / Inspect Model

The Inspect workflow is intended to allow users to review package metadata before extraction.

This may include:

- package ID
- sender identity
- creation time
- signature status
- manifest integrity
- package structure
- recipient mode

This gives recipients and operators confidence that a package is authentic before opening it.

---

## Vault Architecture

Vaults are intended to provide encrypted storage containers for protected data at rest.

Vault workflows may include:

- encrypted-at-rest storage
- controlled mounting
- secure access boundaries
- package-style integrity protections

The vault architecture should be understood as protecting stored data, not as defeating endpoint compromise.

---

## Self-Extracting Package Architecture

Self-extracting secure delivery packages generally contain:

- extractor stub
- package header
- encrypted manifest
- encrypted file chunks

The embedded extractor is intended to:

- prompt for password or load recipient key
- verify package structure and integrity
- decrypt files
- extract to a chosen directory

The encrypted payload remains based on the same underlying ObsidianQ package format used elsewhere.

---

## Trust Boundaries

ObsidianQ assumes the following trust boundaries:

### Trusted
- local private key storage under user control
- core cryptographic libraries behaving as expected
- locally verified package contents after authentication succeeds

### Untrusted Until Verified
- incoming package files
- imported public identity metadata
- sender-provided names/emails/devices
- copied text from external sources
- files received from email or network transfer

---

## Security Limitations

ObsidianQ does not guarantee protection against:

- compromised endpoints
- malware/keyloggers
- advanced local memory scraping
- weak user-chosen passwords
- unverified contact identity metadata
- secure deletion limitations on SSD/flash media
- unaudited implementation flaws

See `THREAT_MODEL.md` for additional detail.

---

## Audit Status

ObsidianQ is built using modern cryptographic primitives and authenticated packaging concepts, but it has **not yet undergone a formal independent cryptographic audit**.

As a result:

- review is welcomed
- scrutiny is encouraged
- users should evaluate the project accordingly

---

## Intended Use Cases

ObsidianQ is intended to support:

- secure file encryption
- secure text / clipboard workflows
- trusted contact exchange
- secure delivery to external recipients
- encrypted vault storage
- package verification and inspection
- compliance-friendly encrypted package handling

---

## Long-Term Goals

The architecture is designed to support growth into:

- stronger interoperability
- stable package format versioning
- broader viewer support
- stronger signing and verification workflows
- reproducible package handling
- improved audit and archival confidence

---

## Contact

Questions, review feedback, and responsible disclosure are welcome.

Please see:

- `SECURITY.md`
- `THREAT_MODEL.md`
- `DISCLAIMER.md`
