# ObsidianQ Threat Model

## Purpose

This document describes the security goals, assumptions, and limitations of ObsidianQ.

ObsidianQ is designed to provide strong confidentiality and integrity protections for files, text, vaults, and secure delivery packages using modern cryptographic primitives and authenticated packaging.

This document is intended to help users, reviewers, and contributors understand what ObsidianQ is designed to defend against, and what is outside its scope.

---

## Security Goals

ObsidianQ is designed to provide the following protections:

### 1. Confidentiality of Protected Data
Encrypted files, text, vault contents, and secure delivery packages should not be readable without the required password or private key material.

### 2. Integrity of Protected Data
Tampering with encrypted packages, manifests, metadata, or encrypted chunks should be detected before extraction or decryption succeeds.

### 3. Authenticity of Signed Package Metadata
When package signing is used, recipients should be able to verify that the manifest was created by the expected sender identity and has not been modified.

### 4. Safe Key Exchange Workflows
Trusted contact workflows should allow users to exchange public identities and encrypt data for intended recipients with minimal manual handling.

### 5. Local-First Protection
Encryption and decryption are intended to occur locally on the user’s machine. Private key material is not intended to be uploaded to external services as part of normal product use.

---

## In-Scope Threats

ObsidianQ is intended to mitigate the following threats:

### Offline File Theft
An attacker obtains encrypted `.obsq`, `.obsqv`, or secure delivery package files and attempts to read them without authorization.

### Package Tampering
An attacker modifies encrypted packages, manifests, or file contents in transit or at rest.

### Chunk Reordering / Truncation / Corruption
An attacker attempts to reorder encrypted chunks, remove chunks, append data, or corrupt package structure.

### Unauthorized Recipient Access
An attacker who is not the intended recipient attempts to decrypt a package protected by password or public-key encryption.

### Basic Distribution Channel Risks
An attacker intercepts an emailed or transferred encrypted package but does not possess the required decryption secret.

### Misdelivery Detection
Signed manifests and package verification are intended to help users recognize whether a package came from the expected sender and whether it remains intact.

---

## Out-of-Scope Threats

ObsidianQ is **not** designed to fully protect against the following classes of attack:

### 1. Compromised Endpoint
If the sender or recipient machine is already compromised by malware, keyloggers, remote access tools, or memory scraping malware, ObsidianQ cannot guarantee secrecy of entered passwords, plaintext files, or decrypted output.

### 2. Live Memory Extraction
An attacker with sufficient local privilege may recover passwords, keys, or plaintext from process memory while the application is running.

### 3. Screen Capture / User Surveillance
ObsidianQ does not defend against screen recording, screenshots, shoulder-surfing, or operator observation.

### 4. Weak Password Selection
If a user chooses a weak password, security may be reduced even if Argon2id is used for password hardening.

### 5. Social Engineering / Identity Misbinding
If a user imports the wrong public identity or accepts malicious metadata without verifying the fingerprint through an independent channel, ObsidianQ cannot prevent that trust mistake.

### 6. Operating System or Driver Exploits
Kernel-level compromise, filesystem driver compromise, malicious USB devices, and low-level OS exploitation are out of scope.

### 7. Secure Deletion Guarantees
ObsidianQ may delete temporary files or working files, but secure deletion on SSDs, flash storage, journaling filesystems, and wear-leveled media cannot be guaranteed.

### 8. Side-Channel Resistance Against Advanced Attackers
ObsidianQ is not currently designed or validated as a hardened side-channel resistant implementation for nation-state or lab-grade local attackers.

---

## Trust Assumptions

ObsidianQ assumes:

- The host operating system is functioning normally and is not already compromised.
- Users protect their private keys and passwords appropriately.
- Public identities are verified through an independent trust channel when authenticity matters.
- Cryptographic libraries and dependencies behave as documented.
- The build distributed to users is genuine and has not been tampered with.

---

## Assets Protected

ObsidianQ attempts to protect:

- plaintext file contents
- vault contents
- clipboard-encrypted text
- secure delivery package payloads
- package manifests
- recipient access controls
- private keys stored locally
- sender identity metadata and fingerprints

---

## Assets Not Fully Protected

ObsidianQ does not guarantee protection of:

- plaintext after the user extracts or opens it
- files written to insecure directories by the user
- screenshots, logs, or copied plaintext outside the tool
- passwords entered into compromised systems
- temporary decrypted artifacts if the operating environment is compromised

---

## Threat Model by Feature

### File Encryption
Protects files against offline theft and tampering. Assumes the user protects the password or private key.

### Text / Clipboard Encryption
Protects copied or pasted content while packaged in encrypted form. Does not protect plaintext that has already been copied into insecure apps or logs.

### Vaults
Protect encrypted-at-rest storage and controlled access to contents. Do not protect plaintext being actively viewed or edited on a compromised machine.

### Secure Contacts
Supports trust establishment and recipient key management. Does not replace fingerprint verification through an independent channel.

### Secure Delivery Packages
Protect confidentiality and package integrity during transfer and support sender verification when signing is used.

### Inspect / Verification Mode
Helps detect tampering, identify sender metadata, and validate package structure before extraction.

---

## Cryptographic Abuse Resistance Goals

ObsidianQ is designed so that:

- encrypted chunks are authenticated
- package metadata is bound into verification logic
- tampering should fail closed
- invalid or corrupted packages should be rejected rather than partially trusted
- manifest verification and signature verification should happen before extraction when applicable

---

## Post-Quantum Considerations

ObsidianQ includes support for post-quantum public-key workflows using ML-KEM / Kyber-family mechanisms where configured.

Password-based encryption remains rooted in symmetric cryptography and password quality. Public-key workflows aim to improve long-term resistance to future advances in large-scale quantum computing.

Post-quantum support does not eliminate the need for:

- strong passwords
- endpoint hygiene
- identity verification
- software review

---

## Operational Recommendations

For best results:

- verify trusted contact fingerprints through a second channel
- keep private keys backed up securely
- use strong, unique passwords
- keep the application updated
- treat decrypted files as sensitive once extracted
- avoid decrypting sensitive material on untrusted systems

---

## Current Security Status

ObsidianQ uses modern cryptographic primitives and is designed with authenticated packaging and verification in mind.

However:

- it has **not yet undergone a formal independent cryptographic audit**
- it should be considered a security-sensitive project still benefiting from review, testing, and scrutiny
- users should evaluate it accordingly before relying on it for high-risk or mission-critical use

---

## Feedback

Security review, critique, and responsible disclosure are welcome.

Please see `SECURITY.md` for vulnerability reporting guidance.
