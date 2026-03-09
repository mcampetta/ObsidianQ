ObsidianQ Public Identity Specification

Version 1 (Draft)

1. Purpose

The ObsidianQ Public Identity format provides a human-friendly wrapper around the cryptographic public key used for encrypted file exchange.

The format allows optional metadata such as:

name

email

device

creation timestamp

This improves usability when exchanging keys while preserving cryptographic correctness.

The metadata does not affect the key itself and must never be trusted automatically.

Users must confirm identity details when importing.

2. Design Goals

The format must:

• Remain compatible with the existing encryption engine
• Preserve the existing raw public key bytes
• Allow optional metadata
• Be easy to copy/paste
• Be easy to parse
• Be future-extensible
• Support file or clipboard exchange

3. File Extension

Recommended file extension:

.obsqpub

Example:

alice.obsqpub
4. Clipboard Format

Public identities may be exchanged via clipboard.

The format must be text-based and delimited.

Example:

-----BEGIN OBSIDIANQ PUBLIC IDENTITY-----
version:1
name:Alice Johnson
email:alice@example.com
device:Alice Laptop
created:2026-03-06T14:22:01Z
algorithm:ML-KEM-768
fingerprint:8A4F2D33E918F2A1

key:
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8...
-----END OBSIDIANQ PUBLIC IDENTITY-----
5. Field Definitions
version
version:1

Format version.

Required.

name
name:Alice Johnson

Human-readable name.

Optional.

Used for UI display only.

email
email:alice@example.com

Optional contact identifier.

Used only for UI display.

device
device:Alice Laptop

Optional.

Useful when users generate multiple identities.

created
created:2026-03-06T14:22:01Z

ISO-8601 timestamp.

Optional but recommended.

algorithm

Example:

algorithm:ML-KEM-768

Indicates the key algorithm used.

Required.

fingerprint

Example:

fingerprint:8A4F2D33E918F2A1

Computed fingerprint of the public key.

Required.

Used for identity verification.

key

The Base64 encoded public key.

Example:

key:
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8...

Required.

The cryptographic key itself.

6. Fingerprint Generation

Fingerprint should be derived from the raw public key bytes.

Recommended algorithm:

BLAKE3(public_key_bytes)

Truncate to:

8 or 16 bytes

Display format:

8A4F 2D33 E918 F2A1

Used for identity verification.

7. Backwards Compatibility

ObsidianQ must continue to support importing raw Base64 public keys.

Importer logic:

if text contains BEGIN OBSIDIANQ PUBLIC IDENTITY
    parse identity
else
    treat input as raw public key

If raw key detected:

name: unknown

User prompted to assign a name.

8. Security Considerations

Metadata fields are not authenticated.

They must be treated as untrusted hints.

When importing:

Parse metadata

Display to user

Allow user to edit

Require confirmation before adding contact

Fingerprint remains the only reliable identifier.

9. UI Behavior

When importing a key, the UI should display:

Contact Detected

Name: Alice Johnson
Email: alice@example.com
Device: Alice Laptop

Fingerprint
8A4F 2D33 E918 F2A1

[ Accept Contact ]  [ Edit ]

User must confirm before storing.

10. Export Behavior

Exporting identity should create:

martin.obsqpub

File contains the identity block.

Users can also copy the identity to clipboard.

11. CLI Changes

The CLI must support:

Export public identity

Example:

obsidianq key export-public

Output:

-----BEGIN OBSIDIANQ PUBLIC IDENTITY-----
...
Export to file
obsidianq key export-public --output alice.obsqpub
Import identity
obsidianq contacts import alice.obsqpub
Generate key with metadata
obsidianq key generate --name "Alice Johnson" --email alice@example.com

Metadata stored locally for export.