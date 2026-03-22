# ObsidianQ Native Vault Format v1 (`.vault`)

A single-file encrypted directory tree with crash-safe dual-slot superblocks,
per-block AEAD integrity, and read/write WinFSP mount support.

---

## Overview

| Property | Value |
|----------|-------|
| Extension | `.vault` (legacy `.obsqv` accepted) |
| Block size (default) | 65,536 bytes on disk |
| Usable bytes per block | 65,520 (block_size − 16 AEAD tag) |
| Max vault capacity | ≈ 32 GiB (single BAT block) |
| Max file size (v1) | ≈ 511 MiB (single-level index, 8190 blocks) |
| Crash safety | Dual-slot superblock commit protocol |
| Nonce scheme | Deterministic HKDF (no nonce storage) |
| Key derivation | Argon2id (password) or Kyber Round 3 recipient mode |
| AEAD suites | XChaCha20-Poly1305, AES-256-GCM |

---

## On-disk Layout

```
Offset        Size    Description
──────────────────────────────────────────────────────────────
0             2048    Immutable section (magic, keys, MAC)
2048           128    Superblock A
2176           128    Superblock B
2304     block_size   Block 0  (BAT block)
2304 + i×block_size  block_size   Block i
```

All blocks are exactly `block_size` bytes on disk.  The final 16 bytes of
every block is the AEAD authentication tag; usable plaintext = `block_size − 16`.

---

## Immutable Section (2048 bytes, offset 0)

Padded to exactly 2048 bytes with zero bytes.

| Field | Size | Description |
|-------|------|-------------|
| magic | 9 | `OBSQVAULT` |
| version | 1 | `0x01` |
| mode | 1 | `0x00` = Password, `0x01` = recipient mode (Kyber Round 3 legacy layout) |
| suite | 1 | `0x00` = XChaCha20-Poly1305, `0x01` = AES-256-GCM |
| flags | 1 | Reserved, must be `0x00` |
| block_size | 4 (u32 LE) | Block size in bytes (default 65,536) |
| file_id | 16 | Random 128-bit vault identifier |
| kem_data_len | 2 (u16 LE) | Byte length of `kem_data` |
| kem_data | variable | Password mode: 32-byte Argon2 salt; recipient mode: 1088-byte Kyber Round 3 ciphertext ‖ 32-byte HKDF salt |
| immutable_mac | 32 | `BLAKE3-keyed(master_key, "obsidianq-v1-obsv-imm\x00" ‖ all fields above)` |
| _padding | fills to 2048 | Zero bytes |

The `immutable_mac` also serves as the `header_hash` for all per-block KDF calls.

---

## Superblock (128 bytes, dual-slot)

Two superblocks sit at fixed offsets 2048 and 2176.  On each commit, the
*inactive* slot is written atomically; the active slot remains valid until the
next commit.  On open, both slots are MAC-verified; the slot with the valid MAC
and the higher `commit_counter` wins.

| Field | Size | Description |
|-------|------|-------------|
| commit_counter | 8 (u64 LE) | Monotonically increasing; used to pick the current slot |
| total_block_count | 8 (u64 LE) | Current number of data blocks |
| bat_block_count | 4 (u32 LE) | Number of leading BAT blocks (always 1 in v1) |
| root_dir_block | 8 (u64 LE) | Index of the root directory block |
| _reserved | 68 | Zero bytes |
| slot_mac | 32 | `BLAKE3-keyed(master_key, "obsidianq-v1-obsv-super\x00" ‖ all fields above)` |

Total: 8 + 8 + 4 + 8 + 68 + 32 = **128 bytes** ✓

### Commit Protocol (crash-safe)

```
1. Write all dirty data / directory blocks → fsync
2. Write updated BAT block(s) → fsync
3. Increment commit_counter; write new superblock to INACTIVE slot → fsync
```

- Crash at steps 1–2: old superblock still valid; consistent prior state.
- Crash at step 3: new slot has invalid MAC; open falls back to old slot.
- Orphaned dirty blocks are a storage leak only; no data corruption.

---

## Block Allocation Table (BAT)

Block 0 is always the BAT block.  Its plaintext is a raw bit array:

- Bit `i` = 1 → block `i` is allocated; 0 → free.
- One 64 KiB BAT block covers 65,520 × 8 = **524,160 blocks** ≈ 32 GiB.
- Bits 0 (BAT itself) and 1 (root dir) are always 1.
- The BAT is loaded into memory on open and flushed atomically on commit.

---

## Directory Block (usable = 65,520 bytes)

Each directory is stored in one or more chained directory blocks.

### Block Header (16 bytes)
| Field | Size | Description |
|-------|------|-------------|
| entry_count | 2 (u16 LE) | Non-free entries in this block |
| _flags | 2 | Reserved, 0 |
| next_dir_block | 8 (u64 LE) | Next continuation block index; `u64::MAX` = none |
| _reserved | 4 | Zero bytes |

### Entries: 255 × DirEntry (256 bytes each = 65,280 bytes)

### Trailing pad: 224 bytes (zeros)

Total: 16 + 65,280 + 224 = **65,520 bytes** ✓

---

## Directory Entry (256 bytes)

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| entry_type | 0 | 1 | `0` = free, `1` = file, `2` = directory |
| attr | 1 | 1 | `bit 0` = hidden, `bit 1` = read-only |
| name_len | 2 | 1 | UTF-8 byte length of name (1–208) |
| _pad | 3 | 1 | Zero |
| size | 4 | 8 (u64 LE) | Plaintext file size; 0 for directories |
| index_block | 12 | 8 (u64 LE) | Index block for files; dir block for directories; `u64::MAX` = empty |
| block_count | 20 | 4 (u32 LE) | Allocated data blocks |
| created | 24 | 8 (u64 LE) | Windows FILETIME (100-ns intervals since 1601-01-01) |
| modified | 32 | 8 (u64 LE) | Windows FILETIME |
| accessed | 40 | 8 (u64 LE) | Windows FILETIME |
| name | 48 | 208 | UTF-8 name, null-padded |

Total: 4 + 8 + 8 + 4 + 24 + 208 = **256 bytes** ✓

---

## File Index Block (usable = 65,520 bytes)

```
block_ptrs: [u64; 8190]    // data-block indices; u64::MAX = unallocated
```

65,520 / 8 = **8,190** pointers per block.  Maximum file size (v1):
8,190 × 65,520 = **536,597,800 bytes ≈ 511 MiB**.

The entire index block is cached in memory when a file is opened, giving O(1)
random access to any byte offset within the file.

---

## File Data Block (usable = 65,520 bytes)

Pure file content; no header.  Byte range `[offset, offset+len)` maps to:

```
block_num    = offset / 65520
block_offset = offset % 65520
data_block   = index_block.block_ptrs[block_num]
```

---

## Per-block Cryptography

All block crypto reuses the existing `obsidianq-core` primitives — zero new
crypto code is introduced in the vault layer.

```
chunk_key = kdf::derive_chunk_key(master_key, &immutable_mac, block_idx)
aad       = aead::build_aad(&immutable_mac, block_idx)   // 40 bytes

encrypt:  ciphertext = aead::encrypt_chunk(suite, &chunk_key, &file_id, block_idx, plaintext, &aad)
decrypt:  plaintext  = aead::decrypt_chunk(suite, &chunk_key, &file_id, block_idx, ciphertext, &aad)
```

The `immutable_mac` (32 bytes) binds every block to this specific vault
instance.  A block from a different vault decrypts to garbage and fails the
AEAD tag verification.

---

## Key Derivation

### Password mode
```
salt        ← random 32 bytes (stored in kem_data field)
master_key  ← Argon2id(password, salt, m=64 MiB, t=3, p=4)
```

### Recipient mode (Kyber Round 3 legacy layout)
```
(ct, ss)    ← Kyber768-R3.Encapsulate(ek)        // ct = 1088 bytes
hkdf_salt   ← random 32 bytes
master_key  ← HKDF-SHA256(ikm=ss, salt=hkdf_salt, info="obsidianq-v1-root")
kem_data    = ct ‖ hkdf_salt                      // stored in header
```

To open: `ss ← Kyber768-R3.Decapsulate(dk, ct)` then derive `master_key` as above.

---

## WinFSP Mount (R/W)

The vault is mounted via `obsidianq vault mount --vault <file> --drive Z`.
The WinFSP filesystem (`vault_vfs.rs`) provides:

- **Read/write** access (no `ReadOnlyVolume` flag)
- All standard file/directory operations: create, open, read, write, delete, rename, truncate
- Crash-safe flush on every WinFSP `Flush` callback and clean unmount
- Dirty-block write cache: changes are in-memory until flushed
- Volume label: `ObsidianQV`

The mount process uses a named Windows event
(`Global\ObsidianQ_VaultMount_{LETTER}`) for cross-process unmount signalling.

---

## CLI Reference

```
obsidianq vault create  --out <file.vault>
                        [--max-size <N[M|G]>]
                        [--block-size 65536]
                        [--password | --password-stdin | --pubkey <key>]
                        [--suite xchacha20 | aesgcm]

obsidianq vault add     --vault <file.vault> --src <local_path>
                        [--dest /vault/path]
                        [--password-stdin | --privkey <key>]

obsidianq vault extract --vault <file.vault> --dest <local_dir>
                        [--path /vault/path]
                        [--password-stdin | --privkey <key>]

obsidianq vault ls      --vault <file.vault> [--path /dir] [--recursive]
                        [--password-stdin | --privkey <key>]

obsidianq vault remove  --vault <file.vault> --path /vault/file
                        [--password-stdin | --privkey <key>]

obsidianq vault mount   --vault <file.vault> --drive Z
                        [--password-stdin | --privkey <key>]

obsidianq vault unmount --drive Z
```

---

## Limitations (v1)

| Limitation | Limit | Future fix |
|------------|-------|------------|
| Max file size | ≈ 511 MiB | Double-indirect index block (v2) |
| Max vault size | ≈ 32 GiB | Multi-BAT-block support (v2) |
| Max files per directory | 255 per block (chained) | Already unlimited via chaining |
| Concurrency | Single Mutex (serialized) | RwLock + per-file locking (v2) |
| Compression | None | Per-block LZ4/zstd option (v2) |
