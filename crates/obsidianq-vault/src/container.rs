//! `VaultContainer` — the main public API for reading and writing `.vault` vaults.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use obsidianq_core::crypto::kdf::MasterKey;
use obsidianq_core::format::{Mode, SuiteId};

use crate::bat::BlockAllocationTable;
use crate::crypto::{read_block, vault_mac, write_block};
use crate::dir;
use crate::format::{
    parse_index_block, serialize_index_block, serialize_index_block_raw,
    superblock_offsets_for_version, DirBlock, DirEntry, ImmutableHeader, Superblock, ENTRY_DIR,
    ENTRY_FILE, ENTRY_FREE, ENTRY_NAME_MAX, INDEX_CHAIN_SENTINEL, INDEX_DATA_PTRS_PER_CHAIN_BLOCK,
    INDEX_PTRS_PER_BLOCK,
};
use crate::{EntryInfo, Result, VaultError};

// ---------------------------------------------------------------------------
// Domain labels for MAC computation
// ---------------------------------------------------------------------------
const DOMAIN_IMM: &[u8] = b"obsidianq-v1-obsv-imm";
const DOMAIN_SUPER: &[u8] = b"obsidianq-v1-obsv-super";

// ---------------------------------------------------------------------------
// CreateParams
// ---------------------------------------------------------------------------

/// Parameters for creating a new `.vault` vault.
pub struct CreateParams {
    pub master_key: MasterKey,
    /// KEM data to embed in the header (32-byte Argon2 salt or KEM-CT ‖ HKDF-salt).
    pub kem_data: Vec<u8>,
    pub mode: Mode,
    pub suite: SuiteId,
    /// Random 16-byte file ID (caller must generate).
    pub file_id: [u8; 16],
    /// Block size in bytes (default 65536).
    pub block_size: u32,
    /// Pre-allocate N extra blocks (0 = auto-grow).
    pub initial_blocks: u64,
}

// ---------------------------------------------------------------------------
// VaultFileHandle
// ---------------------------------------------------------------------------

/// Cached state for an open file or directory in the vault.
#[derive(Debug, Clone)]
pub struct VaultFileHandle {
    /// Vault-absolute path (e.g. "/docs/readme.txt").
    pub path: String,
    pub is_dir: bool,
    /// Cached file → data-block pointer mapping (O(1) random access).
    /// Empty for directories. Entries are u64::MAX for unallocated blocks.
    pub block_map: Vec<u64>,
    pub size: u64,
    pub attr: u8,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
}

// ---------------------------------------------------------------------------
// VaultContainer
// ---------------------------------------------------------------------------

pub struct VaultContainer {
    pub(crate) file: File,
    pub(crate) header: ImmutableHeader,
    pub(crate) master_key: Arc<MasterKey>,
    /// The `immutable_mac` value used as the `header_hash` for all block KDF.
    pub(crate) header_hash: [u8; 32],
    pub(crate) bat: BlockAllocationTable,
    /// Plaintext dirty cache: block_idx → plaintext (usable_bytes long).
    pub(crate) dirty: HashMap<u64, Vec<u8>>,
    pub(crate) active_slot: u8, // 0 = A, 1 = B
    pub(crate) commit_counter: u64,
    pub(crate) total_block_count: u64,
    pub(crate) root_dir_block: u64,
    pub(crate) usable_bytes: usize,
    pub(crate) superblock_a_offset: u64,
    pub(crate) superblock_b_offset: u64,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn now_windows_time() -> u64 {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs * 10_000_000 + EPOCH_DIFF
}

impl VaultContainer {
    // ------------------------------------------------------------------
    // Block I/O (raw: dirty cache + disk)
    // ------------------------------------------------------------------

    /// Read a plaintext block: check dirty cache first, then decrypt from disk.
    pub(crate) fn read_plaintext_block(&mut self, block_idx: u64) -> Result<Vec<u8>> {
        if let Some(plain) = self.dirty.get(&block_idx) {
            return Ok(plain.clone());
        }
        // Verify the block exists on disk (block_idx < total_block_count).
        if block_idx >= self.total_block_count {
            // Return zeroed plaintext for blocks beyond current file size.
            return Ok(vec![0u8; self.usable_bytes]);
        }
        let header = self.header.clone();
        let master_key = Arc::clone(&self.master_key);
        let hash = self.header_hash;
        read_block(&mut self.file, &header, &*master_key, &hash, block_idx)
    }

    /// Put plaintext in dirty cache (overwrites any previous entry).
    pub(crate) fn mark_block_dirty(&mut self, block_idx: u64, plaintext: Vec<u8>) {
        // Expand total_block_count if this block extends the file.
        if block_idx >= self.total_block_count {
            self.total_block_count = block_idx + 1;
        }
        self.dirty.insert(block_idx, plaintext);
    }

    /// Allocate one free data block and return its index.
    pub(crate) fn alloc_block(&mut self) -> Result<u64> {
        self.bat.alloc(&mut self.total_block_count)
    }

    /// Free a data block (updates BAT; does not zero the on-disk content).
    fn free_block(&mut self, block_idx: u64) {
        self.bat.free(block_idx);
        self.dirty.remove(&block_idx);
    }

    // ------------------------------------------------------------------
    // Block map (file index block) helpers
    // ------------------------------------------------------------------

    /// Read the block_map from a file's index block (from dirty or disk).
    fn load_block_map(&mut self, index_block: u64) -> Result<Vec<u64>> {
        if index_block == u64::MAX {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut current = index_block;
        let mut hops = 0usize;
        loop {
            hops += 1;
            if hops > 1_000_000 {
                return Err(VaultError::FormatError("index chain loop detected".into()));
            }
            let plain = self.read_plaintext_block(current)?;
            let ptrs = parse_index_block(&plain);
            let sentinel = ptrs
                .get(INDEX_DATA_PTRS_PER_CHAIN_BLOCK)
                .copied()
                .unwrap_or(u64::MAX);
            let next = ptrs
                .get(INDEX_DATA_PTRS_PER_CHAIN_BLOCK + 1)
                .copied()
                .unwrap_or(u64::MAX);

            if sentinel == INDEX_CHAIN_SENTINEL {
                out.extend(ptrs.iter().take(INDEX_DATA_PTRS_PER_CHAIN_BLOCK).copied());
                if next == u64::MAX {
                    break;
                }
                current = next;
            } else {
                out.extend(ptrs);
                break;
            }
        }
        while out.last().copied() == Some(u64::MAX) {
            out.pop();
        }
        Ok(out)
    }

    fn collect_index_chain(&mut self, index_block: u64) -> Result<Vec<u64>> {
        if index_block == u64::MAX {
            return Ok(Vec::new());
        }
        let mut chain = Vec::new();
        let mut current = index_block;
        let mut hops = 0usize;
        loop {
            hops += 1;
            if hops > 1_000_000 {
                return Err(VaultError::FormatError("index chain loop detected".into()));
            }
            chain.push(current);
            let plain = self.read_plaintext_block(current)?;
            let ptrs = parse_index_block(&plain);
            let sentinel = ptrs
                .get(INDEX_DATA_PTRS_PER_CHAIN_BLOCK)
                .copied()
                .unwrap_or(u64::MAX);
            if sentinel != INDEX_CHAIN_SENTINEL {
                break;
            }
            let next = ptrs
                .get(INDEX_DATA_PTRS_PER_CHAIN_BLOCK + 1)
                .copied()
                .unwrap_or(u64::MAX);
            if next == u64::MAX {
                break;
            }
            current = next;
        }
        Ok(chain)
    }

    fn store_block_map(&mut self, index_block: u64, block_map: &[u64]) -> Result<()> {
        let mut chain = self.collect_index_chain(index_block)?;
        if chain.is_empty() {
            return Err(VaultError::FormatError("missing index block".into()));
        }

        let need_chain = block_map.len() > INDEX_PTRS_PER_BLOCK;
        let chunks = if need_chain {
            block_map.len().div_ceil(INDEX_DATA_PTRS_PER_CHAIN_BLOCK)
        } else {
            1
        };

        while chain.len() < chunks {
            chain.push(self.alloc_block()?);
        }
        if chain.len() > chunks {
            for blk in chain.iter().skip(chunks) {
                self.free_block(*blk);
            }
            chain.truncate(chunks);
        }

        for i in 0..chunks {
            let mut ptrs = vec![u64::MAX; INDEX_PTRS_PER_BLOCK];
            if need_chain {
                let start = i * INDEX_DATA_PTRS_PER_CHAIN_BLOCK;
                let end = (start + INDEX_DATA_PTRS_PER_CHAIN_BLOCK).min(block_map.len());
                for (slot, &ptr) in block_map[start..end].iter().enumerate() {
                    ptrs[slot] = ptr;
                }
                if i < chunks - 1 {
                    ptrs[INDEX_DATA_PTRS_PER_CHAIN_BLOCK] = INDEX_CHAIN_SENTINEL;
                    ptrs[INDEX_DATA_PTRS_PER_CHAIN_BLOCK + 1] = chain[i + 1];
                }
            } else {
                for (slot, &ptr) in block_map.iter().take(INDEX_PTRS_PER_BLOCK).enumerate() {
                    ptrs[slot] = ptr;
                }
            }
            let plain = serialize_index_block_raw(&ptrs, self.usable_bytes);
            self.mark_block_dirty(chain[i], plain);
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Superblock MAC
    // ------------------------------------------------------------------

    fn compute_super_mac(&self, sb: &Superblock) -> [u8; 32] {
        vault_mac(&self.master_key, DOMAIN_SUPER, &sb.body_bytes())
    }

    fn write_superblock(&mut self, slot: u8, sb: &mut Superblock) -> Result<()> {
        sb.slot_mac = self.compute_super_mac(sb);
        let offset = if slot == 0 {
            self.superblock_a_offset
        } else {
            self.superblock_b_offset
        };
        self.file.seek(SeekFrom::Start(offset))?;
        sb.write_to(&mut self.file)?;
        self.file.flush()?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // create / open
    // ------------------------------------------------------------------

    /// Create a new vault file at `path`.
    pub fn create(path: &Path, params: CreateParams) -> Result<Self> {
        let usable = (params.block_size - 16) as usize;

        // Build the header (without MAC).
        let mut header = ImmutableHeader {
            version: crate::format::VERSION,
            mode: params.mode,
            suite: params.suite,
            flags: 0,
            block_size: params.block_size,
            file_id: params.file_id,
            kem_data: params.kem_data,
            immutable_mac: [0u8; 32],
        };

        // Compute and set the immutable MAC.
        let canonical = header.canonical_bytes();
        let master_key = Arc::new(params.master_key);
        let immutable_mac = vault_mac(&master_key, DOMAIN_IMM, &canonical);
        header.immutable_mac = immutable_mac;
        let header_hash = immutable_mac; // used for all per-block KDF
        let (superblock_a_offset, superblock_b_offset, _) =
            superblock_offsets_for_version(header.version)?;

        // Create file.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;

        // Write immutable section.
        file.seek(SeekFrom::Start(0))?;
        header.write_to(&mut file)?;

        // Write placeholder superblocks (zeros, invalid MAC).
        let zero_sb = Superblock::default();
        file.seek(SeekFrom::Start(superblock_a_offset))?;
        zero_sb.write_to(&mut file)?;
        file.seek(SeekFrom::Start(superblock_b_offset))?;
        zero_sb.write_to(&mut file)?;

        file.flush()?;

        // Initial BAT: blocks 0 (BAT) and 1 (root dir) are used.
        let bat = BlockAllocationTable::new(usable);

        // Dirty cache: root dir block (block 1).
        let root_dir_db = DirBlock::empty();
        let root_dir_plain = root_dir_db.to_bytes(usable);
        let mut dirty = HashMap::new();
        dirty.insert(1u64, root_dir_plain);

        let total_block_count = 2u64; // blocks 0 (BAT) + 1 (root dir)

        // Handle initial_blocks pre-allocation.
        let total_block_count = if params.initial_blocks > 0 {
            total_block_count.max(params.initial_blocks + 2)
        } else {
            total_block_count
        };

        let mut vc = VaultContainer {
            file,
            header,
            master_key,
            header_hash,
            bat,
            dirty,
            active_slot: 1, // so flush will write to slot 0 first
            commit_counter: 0,
            total_block_count,
            root_dir_block: 1,
            usable_bytes: usable,
            superblock_a_offset,
            superblock_b_offset,
        };

        // Flush (writes BAT block 0, root dir block 1, commits superblock A).
        vc.flush()?;
        Ok(vc)
    }

    /// Open an existing vault for read/write.
    pub fn open(path: &Path, master_key: MasterKey) -> Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;

        // Read and parse immutable header.
        file.seek(SeekFrom::Start(0))?;
        let header = ImmutableHeader::read_from(&mut file)?;
        let usable = header.usable_bytes();
        let (superblock_a_offset, superblock_b_offset, _) =
            superblock_offsets_for_version(header.version)?;

        // Verify the immutable MAC.
        let master_key = Arc::new(master_key);
        let canonical = header.canonical_bytes();
        let expected_mac = vault_mac(&master_key, DOMAIN_IMM, &canonical);
        if !constant_time_eq(&expected_mac, &header.immutable_mac) {
            return Err(VaultError::HeaderMacMismatch);
        }
        let header_hash = header.immutable_mac;

        // Read both superblocks; pick the valid one with the highest commit_counter.
        file.seek(SeekFrom::Start(superblock_a_offset))?;
        let sb_a = Superblock::read_from(&mut file)?;
        file.seek(SeekFrom::Start(superblock_b_offset))?;
        let sb_b = Superblock::read_from(&mut file)?;

        let mac_a_ok = {
            let expected = vault_mac(&master_key, DOMAIN_SUPER, &sb_a.body_bytes());
            constant_time_eq(&expected, &sb_a.slot_mac)
        };
        let mac_b_ok = {
            let expected = vault_mac(&master_key, DOMAIN_SUPER, &sb_b.body_bytes());
            constant_time_eq(&expected, &sb_b.slot_mac)
        };

        let (active_slot, sb) = match (mac_a_ok, mac_b_ok) {
            (true, true) => {
                if sb_a.commit_counter >= sb_b.commit_counter {
                    (0u8, sb_a)
                } else {
                    (1u8, sb_b)
                }
            }
            (true, false) => (0, sb_a),
            (false, true) => (1, sb_b),
            (false, false) => return Err(VaultError::NoValidSuperblock),
        };

        let total_block_count = sb.total_block_count;
        let root_dir_block = sb.root_dir_block;
        let commit_counter = sb.commit_counter;

        // Load BAT block 0 from disk.
        let bat_plain = read_block(&mut file, &header, &*master_key, &header_hash, 0)?;
        let bat = BlockAllocationTable::from_bytes(&bat_plain);

        Ok(VaultContainer {
            file,
            header,
            master_key,
            header_hash,
            bat,
            dirty: HashMap::new(),
            active_slot,
            commit_counter,
            total_block_count,
            root_dir_block,
            usable_bytes: usable,
            superblock_a_offset,
            superblock_b_offset,
        })
    }

    // ------------------------------------------------------------------
    // flush — dual-slot commit protocol
    // ------------------------------------------------------------------

    /// Returns true if there are any uncommitted dirty blocks in memory.
    pub fn has_dirty_blocks(&self) -> bool {
        !self.dirty.is_empty()
    }

    /// Commit all pending changes using the dual-slot superblock protocol.
    ///
    /// 1. Write all dirty data/dir blocks → sync
    /// 2. Write BAT block(s) → sync
    /// 3. Write new superblock to INACTIVE slot → sync
    /// 4. Old superblock remains valid until overwritten next commit.
    pub fn flush(&mut self) -> Result<()> {
        let header = self.header.clone();
        let master_key = Arc::clone(&self.master_key);
        let hash = self.header_hash;

        // Step 1: write dirty data/dir blocks (skip BAT block 0 — handled in step 2).
        let dirty_keys: Vec<u64> = self.dirty.keys().cloned().filter(|&k| k != 0).collect();
        for idx in dirty_keys {
            let plain = self.dirty[&idx].clone();
            write_block(&mut self.file, &header, &*master_key, &hash, idx, &plain)?;
            self.dirty.remove(&idx);
        }
        self.file.flush()?;

        // Step 2: write BAT block 0.
        let bat_plain: Vec<u8> = self.bat.as_bytes().to_vec();
        write_block(&mut self.file, &header, &*master_key, &hash, 0, &bat_plain)?;
        self.dirty.remove(&0);
        self.bat.mark_clean();
        self.file.flush()?;

        // Step 3: write new superblock to the INACTIVE slot.
        self.commit_counter += 1;
        let inactive_slot = 1 - self.active_slot;
        let mut new_sb = Superblock {
            commit_counter: self.commit_counter,
            total_block_count: self.total_block_count,
            bat_block_count: 1,
            root_dir_block: self.root_dir_block,
            slot_mac: [0u8; 32],
        };
        self.write_superblock(inactive_slot, &mut new_sb)?;
        self.active_slot = inactive_slot;

        Ok(())
    }

    // ------------------------------------------------------------------
    // FS operations — metadata
    // ------------------------------------------------------------------

    /// Return metadata for `path`.
    pub fn stat(&mut self, path: &str) -> Result<EntryInfo> {
        let path = path.trim_end_matches('/');
        if path.is_empty() || path == "/" {
            let now = now_windows_time();
            return Ok(EntryInfo {
                name: String::new(),
                is_dir: true,
                size: 0,
                attr: 0,
                created: now,
                modified: now,
                accessed: now,
            });
        }
        let (_, _, entry) = dir::resolve_entry(self, path)?;
        Ok(entry_to_info(&entry))
    }

    /// List all non-free entries in the directory at `path`.
    pub fn list_dir(&mut self, path: &str) -> Result<Vec<EntryInfo>> {
        let dir_block = dir::resolve_dir_block(self, path)?;
        let mut result = Vec::new();
        let mut current = dir_block;
        loop {
            let plain = self.read_plaintext_block(current)?;
            let db = DirBlock::from_bytes(&plain);
            for entry in &db.entries {
                if entry.entry_type != ENTRY_FREE {
                    result.push(entry_to_info(entry));
                }
            }
            if db.next_dir_block == u64::MAX {
                break;
            }
            current = db.next_dir_block;
        }
        Ok(result)
    }

    /// Create a directory at `path`.
    pub fn create_dir(&mut self, path: &str) -> Result<()> {
        let (parent_path, name) = dir::split_parent(path)?;
        let parent_dir = dir::resolve_dir_block(self, &parent_path)?;

        if dir::find_entry(self, parent_dir, &name)?.is_some() {
            return Err(VaultError::AlreadyExists(path.to_owned()));
        }
        if name.len() > ENTRY_NAME_MAX {
            return Err(VaultError::FormatError("name too long".into()));
        }

        let usable = self.usable_bytes;
        let dir_block_idx = self.alloc_block()?;
        let new_dir = DirBlock::empty();
        self.mark_block_dirty(dir_block_idx, new_dir.to_bytes(usable));

        let now = now_windows_time();
        let mut entry = DirEntry::free();
        entry.entry_type = ENTRY_DIR;
        entry.name_len = name.len() as u8;
        entry.index_block = dir_block_idx;
        entry.created = now;
        entry.modified = now;
        entry.accessed = now;
        entry.name[..name.len()].copy_from_slice(name.as_bytes());

        dir::add_entry(self, parent_dir, entry)
    }

    /// Remove an empty directory at `path`.
    pub fn remove_dir(&mut self, path: &str) -> Result<()> {
        let (parent_path, name) = dir::split_parent(path)?;
        let parent_dir = dir::resolve_dir_block(self, &parent_path)?;

        let (_, _, entry) = dir::resolve_entry(self, path)?;
        if entry.entry_type != ENTRY_DIR {
            return Err(VaultError::NotADirectory(path.to_owned()));
        }
        if !dir::dir_is_empty(self, entry.index_block)? {
            return Err(VaultError::DirectoryNotEmpty(path.to_owned()));
        }

        // Free the dir block and any continuation blocks.
        let continuations = dir::collect_continuation_blocks(self, entry.index_block)?;
        self.free_block(entry.index_block);
        for blk in continuations {
            self.free_block(blk);
        }

        dir::remove_entry(self, parent_dir, &name)?;
        Ok(())
    }

    /// Create an empty file at `path`.
    pub fn create_file(&mut self, path: &str) -> Result<()> {
        let (parent_path, name) = dir::split_parent(path)?;
        let parent_dir = dir::resolve_dir_block(self, &parent_path)?;

        if dir::find_entry(self, parent_dir, &name)?.is_some() {
            return Err(VaultError::AlreadyExists(path.to_owned()));
        }
        if name.len() > ENTRY_NAME_MAX {
            return Err(VaultError::FormatError("name too long".into()));
        }

        let now = now_windows_time();
        let mut entry = DirEntry::free();
        entry.entry_type = ENTRY_FILE;
        entry.name_len = name.len() as u8;
        entry.index_block = u64::MAX;
        entry.size = 0;
        entry.created = now;
        entry.modified = now;
        entry.accessed = now;
        entry.name[..name.len()].copy_from_slice(name.as_bytes());

        dir::add_entry(self, parent_dir, entry)
    }

    /// Delete a file at `path`.
    pub fn delete_file(&mut self, path: &str) -> Result<()> {
        let (parent_path, name) = dir::split_parent(path)?;
        let parent_dir = dir::resolve_dir_block(self, &parent_path)?;

        let (_, _, entry) = dir::resolve_entry(self, path)?;
        if entry.entry_type == ENTRY_DIR {
            return Err(VaultError::IsADirectory(path.to_owned()));
        }

        // Free all data blocks and the index block.
        if entry.index_block != u64::MAX {
            let block_map = self.load_block_map(entry.index_block)?;
            for &ptr in &block_map {
                if ptr != u64::MAX {
                    self.free_block(ptr);
                }
            }
            for blk in self.collect_index_chain(entry.index_block)? {
                self.free_block(blk);
            }
        }

        dir::remove_entry(self, parent_dir, &name)?;
        Ok(())
    }

    /// Rename / move `from` to `to` (both must share the same filesystem).
    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let (from_parent, from_name) = dir::split_parent(from)?;
        let (to_parent, to_name) = dir::split_parent(to)?;

        let from_parent_dir = dir::resolve_dir_block(self, &from_parent)?;
        let to_parent_dir = dir::resolve_dir_block(self, &to_parent)?;

        // Clone the entry, update the name.
        let (_, _, mut entry) = dir::resolve_entry(self, from)?;
        if to_name.len() > ENTRY_NAME_MAX {
            return Err(VaultError::FormatError("target name too long".into()));
        }

        // Reject if destination already exists.
        if dir::find_entry(self, to_parent_dir, &to_name)?.is_some() {
            return Err(VaultError::AlreadyExists(to.to_owned()));
        }

        // Remove from source dir.
        dir::remove_entry(self, from_parent_dir, &from_name)?;

        // Update name in entry.
        entry.name = [0u8; ENTRY_NAME_MAX];
        entry.name_len = to_name.len() as u8;
        entry.name[..to_name.len()].copy_from_slice(to_name.as_bytes());

        // Add to destination dir.
        dir::add_entry(self, to_parent_dir, entry)
    }

    /// Update timestamps for `path`. Pass 0 to leave a field unchanged.
    pub fn set_times(
        &mut self,
        path: &str,
        created: u64,
        modified: u64,
        accessed: u64,
    ) -> Result<()> {
        let (parent_path, name) = dir::split_parent(path)?;
        let dir_block = dir::resolve_dir_block(self, &parent_path)?;
        dir::update_entry(self, dir_block, &name, |e| {
            if created != 0 {
                e.created = created;
            }
            if modified != 0 {
                e.modified = modified;
            }
            if accessed != 0 {
                e.accessed = accessed;
            }
        })
    }

    /// Update file attributes for `path`.
    pub fn set_attr(&mut self, path: &str, attr: u8) -> Result<()> {
        let (parent_path, name) = dir::split_parent(path)?;
        let dir_block = dir::resolve_dir_block(self, &parent_path)?;
        dir::update_entry(self, dir_block, &name, |e| e.attr = attr)
    }

    // ------------------------------------------------------------------
    // FS operations — I/O
    // ------------------------------------------------------------------

    /// Read up to `buf.len()` bytes from `path` starting at `offset`.
    /// Returns the number of bytes actually read.
    pub fn read_range(
        &mut self,
        block_map: &[u64],
        size: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        if offset >= size {
            return Ok(0);
        }
        let usable = self.usable_bytes as u64;
        let avail = (size - offset).min(buf.len() as u64);
        let mut done = 0usize;

        while done < avail as usize {
            let file_offset = offset + done as u64;
            let block_num = (file_offset / usable) as usize;
            let block_off = (file_offset % usable) as usize;

            let remaining_in_block = self.usable_bytes - block_off;
            let to_copy = remaining_in_block.min(avail as usize - done);

            let plain = if block_num < block_map.len() && block_map[block_num] != u64::MAX {
                self.read_plaintext_block(block_map[block_num])?
            } else {
                vec![0u8; self.usable_bytes]
            };

            buf[done..done + to_copy].copy_from_slice(&plain[block_off..block_off + to_copy]);
            done += to_copy;
        }
        Ok(done)
    }

    /// Write `data` to `path` at `offset`, growing the file as needed.
    ///
    /// `block_map` and `size` are updated in place when new blocks are allocated.
    pub fn write_range(
        &mut self,
        path: &str,
        block_map: &mut Vec<u64>,
        size: &mut u64,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let usable = self.usable_bytes as u64;

        // Ensure we have an index block.
        let (parent_path, name) = dir::split_parent(path)?;
        let dir_block = dir::resolve_dir_block(self, &parent_path)?;

        let (_, _, entry) = dir::resolve_entry(self, path)?;
        let mut idx_blk = entry.index_block;

        if idx_blk == u64::MAX {
            // Allocate index block.
            idx_blk = self.alloc_block()?;
            let plain = serialize_index_block(&[], self.usable_bytes);
            self.mark_block_dirty(idx_blk, plain);
            dir::update_entry(self, dir_block, &name, |e| {
                e.index_block = idx_blk;
            })?;
            *block_map = Vec::new();
        } else if block_map.is_empty() {
            *block_map = self.load_block_map(idx_blk)?;
        }

        let mut map_dirty = false;
        let mut done = 0usize;

        while done < data.len() {
            let file_offset = offset + done as u64;
            let block_num = (file_offset / usable) as usize;
            let block_off = (file_offset % usable) as usize;

            // Extend block_map if needed.
            if block_map.len() <= block_num {
                block_map.resize(block_num + 1, u64::MAX);
            }

            let remaining_in_block = self.usable_bytes - block_off;
            let to_write = remaining_in_block.min(data.len() - done);

            // Allocate data block if needed.
            if block_map[block_num] == u64::MAX {
                let new_blk = self.alloc_block()?;
                block_map[block_num] = new_blk;
                map_dirty = true;
                self.mark_block_dirty(new_blk, vec![0u8; self.usable_bytes]);
            }

            let data_blk = block_map[block_num];

            // Read-modify-write: get current plaintext.
            let mut plain = self.read_plaintext_block(data_blk)?;
            plain[block_off..block_off + to_write].copy_from_slice(&data[done..done + to_write]);
            self.mark_block_dirty(data_blk, plain);

            done += to_write;
        }

        // Update index block if block_map grew.
        if map_dirty {
            self.store_block_map(idx_blk, block_map)?;
        }

        // Update file size if we wrote past the current end.
        let new_end = offset + data.len() as u64;
        if new_end > *size {
            *size = new_end;
            dir::update_entry(self, dir_block, &name, |e| {
                e.size = new_end;
                e.modified = now_windows_time();
                let blk_count = ((new_end + usable - 1) / usable) as u32;
                e.block_count = blk_count;
            })?;
        }

        Ok(())
    }

    /// Resize `path` to `new_size` bytes.
    pub fn set_size(
        &mut self,
        path: &str,
        block_map: &mut Vec<u64>,
        size: &mut u64,
        new_size: u64,
    ) -> Result<()> {
        let usable = self.usable_bytes as u64;
        let (parent_path, name) = dir::split_parent(path)?;
        let dir_block = dir::resolve_dir_block(self, &parent_path)?;

        if new_size < *size {
            // Shrink: free data blocks beyond new_size.
            let new_blocks = ((new_size + usable - 1) / usable) as usize;
            let (_, _, entry) = dir::resolve_entry(self, path)?;

            if entry.index_block != u64::MAX {
                if block_map.is_empty() {
                    *block_map = self.load_block_map(entry.index_block)?;
                }
                for idx in new_blocks..block_map.len() {
                    if block_map[idx] != u64::MAX {
                        self.free_block(block_map[idx]);
                        block_map[idx] = u64::MAX;
                    }
                }
                block_map.truncate(new_blocks);
                // Write updated index block(s).
                self.store_block_map(entry.index_block, block_map)?;
            }
        }
        // For growth, the new blocks will be lazily allocated on first write.

        *size = new_size;
        dir::update_entry(self, dir_block, &name, |e| {
            e.size = new_size;
            e.block_count = ((new_size + usable - 1) / usable) as u32;
            e.modified = now_windows_time();
        })?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // open_handle — cache file metadata + block_map
    // ------------------------------------------------------------------

    /// Open a vault path and return a cached handle.
    pub fn open_handle(&mut self, path: &str) -> Result<VaultFileHandle> {
        let path = path.trim_end_matches('/');
        if path.is_empty() || path == "/" {
            let now = now_windows_time();
            return Ok(VaultFileHandle {
                path: "/".to_string(),
                is_dir: true,
                block_map: Vec::new(),
                size: 0,
                attr: 0,
                created: now,
                modified: now,
                accessed: now,
            });
        }

        let (_, _, entry) = dir::resolve_entry(self, path)?;
        let is_dir = entry.entry_type == ENTRY_DIR;
        let block_map = if is_dir {
            Vec::new()
        } else {
            self.load_block_map(entry.index_block)?
        };

        Ok(VaultFileHandle {
            path: path.to_string(),
            is_dir,
            block_map,
            size: entry.size,
            attr: entry.attr,
            created: entry.created,
            modified: entry.modified,
            accessed: entry.accessed,
        })
    }

    // ------------------------------------------------------------------
    // BAT stats
    // ------------------------------------------------------------------

    pub fn free_blocks(&self) -> u64 {
        self.bat.free_block_count_in(self.total_block_count)
    }

    pub fn total_blocks(&self) -> u64 {
        self.total_block_count
    }

    /// Usable plaintext bytes per block (= block_size − 16 AEAD tag bytes).
    pub fn block_usable_bytes(&self) -> u64 {
        self.usable_bytes as u64
    }

    // ------------------------------------------------------------------
    // CLI convenience — import / export
    // ------------------------------------------------------------------

    /// Import a local file into the vault at `vault_path`.
    /// Creates parent directories as needed.
    /// Returns the number of bytes imported.
    pub fn import_file(&mut self, src: &Path, vault_path: &str) -> Result<u64> {
        // Create parent directories if they don't exist.
        self.ensure_parents(vault_path)?;

        // Create the file entry if it doesn't already exist.
        if self.stat(vault_path).is_err() {
            self.create_file(vault_path)?;
        }

        let mut f = File::open(src)?;
        let file_size = f.metadata()?.len();

        let (parent_path, name) = dir::split_parent(vault_path)?;
        let dir_block = dir::resolve_dir_block(self, &parent_path)?;

        // Load existing (or fresh) state.
        let (_, _, entry) = dir::resolve_entry(self, vault_path)?;
        let mut block_map = self.load_block_map(entry.index_block)?;
        let mut size = entry.size;

        let usable = self.usable_bytes;
        let mut buf = vec![0u8; usable];
        let mut offset = 0u64;

        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.write_range(vault_path, &mut block_map, &mut size, offset, &buf[..n])?;
            offset += n as u64;
        }

        // Set final size.
        dir::update_entry(self, dir_block, &name, |e| {
            e.size = file_size;
            e.modified = now_windows_time();
        })?;

        Ok(file_size)
    }

    /// Export `vault_path` to a local file at `dest`.
    /// Returns the number of bytes exported.
    pub fn export_file(&mut self, vault_path: &str, dest: &Path) -> Result<u64> {
        let (_, _, entry) = dir::resolve_entry(self, vault_path)?;
        if entry.entry_type == ENTRY_DIR {
            return Err(VaultError::IsADirectory(vault_path.to_owned()));
        }

        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest)?;
        let block_map = self.load_block_map(entry.index_block)?;
        let size = entry.size;

        if size == 0 {
            return Ok(0);
        }

        let usable = self.usable_bytes;
        let mut buf = vec![0u8; usable];
        let mut offset = 0u64;

        while offset < size {
            let to_read = ((size - offset) as usize).min(usable);
            let n = self.read_range(&block_map, size, offset, &mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            offset += n as u64;
        }

        Ok(size)
    }

    /// Recursively import a local directory tree.
    pub fn import_tree(&mut self, src_dir: &Path, vault_prefix: &str) -> Result<()> {
        use std::fs;
        for entry in fs::read_dir(src_dir)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            let name = entry.file_name().to_string_lossy().to_string();
            let vault_path = if vault_prefix.is_empty() || vault_prefix == "/" {
                format!("/{name}")
            } else {
                format!("{vault_prefix}/{name}")
            };

            if ft.is_dir() {
                self.create_dir(&vault_path).ok(); // ignore "already exists"
                self.import_tree(&entry.path(), &vault_path)?;
            } else if ft.is_file() {
                self.import_file(&entry.path(), &vault_path)?;
            }
        }
        Ok(())
    }

    /// Recursively export a vault subtree to a local directory.
    pub fn export_tree(&mut self, vault_prefix: &str, dest_dir: &Path) -> Result<()> {
        use std::fs;
        fs::create_dir_all(dest_dir)?;

        let entries = self.list_dir(vault_prefix)?;
        for info in entries {
            let vault_path = if vault_prefix == "/" {
                format!("/{}", info.name)
            } else {
                format!("{vault_prefix}/{}", info.name)
            };
            let local_path = dest_dir.join(&info.name);
            if info.is_dir {
                fs::create_dir_all(&local_path)?;
                self.export_tree(&vault_path, &local_path)?;
            } else {
                self.export_file(&vault_path, &local_path)?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Create all parent directories for `path` if they don't exist.
    fn ensure_parents(&mut self, path: &str) -> Result<()> {
        let components = dir::path_components(path);
        if components.len() <= 1 {
            return Ok(());
        }

        let mut current = "/".to_string();
        for component in &components[..components.len() - 1] {
            let next = if current == "/" {
                format!("/{component}")
            } else {
                format!("{current}/{component}")
            };
            if self.stat(&next).is_err() {
                self.create_dir(&next)?;
            }
            current = next;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal utilities
// ---------------------------------------------------------------------------

fn entry_to_info(entry: &DirEntry) -> EntryInfo {
    EntryInfo {
        name: entry.name_str().to_string(),
        is_dir: entry.entry_type == ENTRY_DIR,
        size: entry.size,
        attr: entry.attr,
        created: entry.created,
        modified: entry.modified,
        accessed: entry.accessed,
    }
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    // Constant-time comparison: fold XOR over all bytes.
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
