# Threat Model

This document describes the practical security assumptions for ObsidianQ.

## Primary Goals

- Protect file and package contents at rest
- Support local-only password workflows
- Support recipient-based exchange without requiring a cloud key server
- Preserve metadata verification for delivery packages where signatures are present

## In Scope

- Local encryption and decryption on user-controlled machines
- Password-derived protection for files and delivery packages
- Trusted-contact recipient exchange
- Integrity and metadata verification for supported package formats

## Out of Scope

- Defending against a fully compromised endpoint
- Hiding all metadata from every workflow
- Anonymous communication guarantees
- Formal compliance claims
- Server-side escrow or hosted key recovery

## Operational Assumptions

- Users protect their passwords and private keys
- Users verify contact fingerprints before trusting recipient encryption
- Users keep backups of recovery material
- Users obtain releases from a trusted source and verify integrity where appropriate

## Important Limits

- Recipient encryption wording must reflect the implemented algorithms and formats
- Self-extracting executables are a compatibility workflow, not the safest default delivery path
- Browser-based decrypt workflows are best suited to small and medium packages, not very large archives
