# Security Status

ObsidianQ is an actively developed local-first encryption project. It has not yet completed a formal third-party security audit.

Current status:

- No formal audit or certification claim
- Community review is welcome
- Security issues should be reported privately when possible
- Public wording should remain conservative and match the implemented code paths

Current recipient-encryption note:

- Current trusted-contact recipient exchange uses Kyber Round 3 via `pqcrypto-kyber`
- ObsidianQ does not currently claim FIPS 203 ML-KEM compliance or interoperability

Relevant documents:

- [Threat Model](THREAT_MODEL.md)
- [Security Architecture](docs/SECURITY_ARCHITECTURE.md)
- [Disclaimer](DISCLAIMER.md)

## Reporting Security Issues

Until a dedicated disclosure channel is added, report sensitive issues directly to the project maintainer through a private GitHub security report or other private contact path when available.

Please include:

- affected version or commit
- platform
- reproduction steps
- impact assessment if known

Avoid posting exploit details publicly before the issue has been triaged.
