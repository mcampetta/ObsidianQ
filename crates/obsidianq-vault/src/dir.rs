//! Directory tree operations on VaultContainer.
//!
//! This module is `pub(crate)` — all callers go through `container.rs`.
//!
//! Internal conventions:
//! - Vault paths use forward-slash separator: "/", "/docs/file.txt"
//! - The root directory corresponds to `container.root_dir_block`
//! - `find_entry(container, dir_block, name)` scans the dir block chain
//! - `add_entry(container, dir_block, entry)` appends to the first block
//!   with a free slot (or allocates a continuation block)
//! - `remove_entry(container, dir_block, name)` zeroes the slot in-place

use crate::container::VaultContainer;
use crate::format::{DirBlock, DirEntry, ENTRY_DIR, ENTRY_FREE};
use crate::{Result, VaultError};

// ---------------------------------------------------------------------------
// Path utilities
// ---------------------------------------------------------------------------

/// Split `path` into `(parent_path, leaf_name)`.
/// Returns `Err` if the path is invalid or names the root.
pub(crate) fn split_parent(path: &str) -> Result<(String, String)> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return Err(VaultError::FormatError(
            "cannot operate on root directory this way".into(),
        ));
    }
    match path.rfind('/') {
        None => Ok(("/".to_string(), path.to_string())),
        Some(pos) => {
            let parent = format!("/{}", &path[..pos]);
            let leaf = path[pos + 1..].to_string();
            if leaf.is_empty() {
                return Err(VaultError::FormatError("trailing slash in path".into()));
            }
            Ok((parent, leaf))
        }
    }
}

/// Return path components (excluding leading slash, empty components).
pub(crate) fn path_components(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

/// Resolve a vault path to the index of its containing directory block.
///
/// Returns the block index of the directory containing the final component.
/// For "/" this is `container.root_dir_block`.
pub(crate) fn resolve_dir_block(c: &mut VaultContainer, path: &str) -> Result<u64> {
    let components = path_components(path);
    let mut current = c.root_dir_block;

    for component in &components {
        // Look up `component` in `current` dir block chain.
        match find_entry(c, current, component)? {
            None => return Err(VaultError::NotFound(path.to_owned())),
            Some((block_idx, entry_idx)) => {
                let plain = c.read_plaintext_block(block_idx)?;
                let db = DirBlock::from_bytes(&plain);
                let entry = &db.entries[entry_idx];
                if entry.entry_type != ENTRY_DIR {
                    return Err(VaultError::NotADirectory(component.to_string()));
                }
                current = entry.index_block;
            }
        }
    }
    Ok(current)
}

/// Resolve a path to `(containing_dir_block, entry_idx, entry)`.
///
/// The path must name an existing entry (not root "/").
pub(crate) fn resolve_entry(c: &mut VaultContainer, path: &str) -> Result<(u64, usize, DirEntry)> {
    let (parent_path, name) = split_parent(path)?;
    let dir_block = resolve_dir_block(c, &parent_path)?;

    match find_entry(c, dir_block, &name)? {
        None => Err(VaultError::NotFound(path.to_owned())),
        Some((block_idx, entry_idx)) => {
            let plain = c.read_plaintext_block(block_idx)?;
            let db = DirBlock::from_bytes(&plain);
            Ok((block_idx, entry_idx, db.entries[entry_idx].clone()))
        }
    }
}

// ---------------------------------------------------------------------------
// Entry search
// ---------------------------------------------------------------------------

/// Search `dir_block` (and its continuation chain) for `name`.
///
/// Returns `Some((block_idx, entry_idx))` if found.
pub(crate) fn find_entry(
    c: &mut VaultContainer,
    dir_block: u64,
    name: &str,
) -> Result<Option<(u64, usize)>> {
    let mut current = dir_block;
    loop {
        let plain = c.read_plaintext_block(current)?;
        let db = DirBlock::from_bytes(&plain);

        for (i, entry) in db.entries.iter().enumerate() {
            if entry.entry_type == ENTRY_FREE {
                continue;
            }
            let ename = &entry.name[..entry.name_len as usize];
            if ename == name.as_bytes() {
                return Ok(Some((current, i)));
            }
        }

        if db.next_dir_block == u64::MAX {
            break;
        }
        current = db.next_dir_block;
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Entry mutation
// ---------------------------------------------------------------------------

/// Add `entry` to the first free slot in `dir_block` (or a continuation).
///
/// Allocates a continuation block if all existing blocks are full.
pub(crate) fn add_entry(c: &mut VaultContainer, dir_block: u64, entry: DirEntry) -> Result<()> {
    let usable = c.usable_bytes;
    let mut current = dir_block;
    loop {
        let plain = c.read_plaintext_block(current)?;
        let mut db = DirBlock::from_bytes(&plain);

        // Find a free slot.
        if let Some(pos) = db.entries.iter().position(|e| e.entry_type == ENTRY_FREE) {
            db.entries[pos] = entry;
            db.entry_count = db
                .entries
                .iter()
                .filter(|e| e.entry_type != ENTRY_FREE)
                .count() as u16;
            c.mark_block_dirty(current, db.to_bytes(usable));
            return Ok(());
        }

        // No free slot in this block — follow / allocate continuation.
        if db.next_dir_block == u64::MAX {
            // Allocate a new continuation block.
            let new_block = c.alloc_block()?;
            let new_db = DirBlock::empty();
            c.mark_block_dirty(new_block, new_db.to_bytes(usable));

            // Point current block to continuation.
            db.next_dir_block = new_block;
            c.mark_block_dirty(current, db.to_bytes(usable));
        }
        current = db.next_dir_block;
    }
}

/// Remove the entry named `name` from `dir_block` (or its continuation chain).
///
/// Returns the removed entry so callers can free its data blocks.
pub(crate) fn remove_entry(c: &mut VaultContainer, dir_block: u64, name: &str) -> Result<DirEntry> {
    let usable = c.usable_bytes;
    match find_entry(c, dir_block, name)? {
        None => Err(VaultError::NotFound(name.to_owned())),
        Some((block_idx, entry_idx)) => {
            let plain = c.read_plaintext_block(block_idx)?;
            let mut db = DirBlock::from_bytes(&plain);
            let removed = db.entries[entry_idx].clone();
            db.entries[entry_idx] = DirEntry::free();
            db.entry_count -= 1;
            c.mark_block_dirty(block_idx, db.to_bytes(usable));
            Ok(removed)
        }
    }
}

/// Mutate the entry named `name` in place within `dir_block` (or its chain).
pub(crate) fn update_entry(
    c: &mut VaultContainer,
    dir_block: u64,
    name: &str,
    f: impl FnOnce(&mut DirEntry),
) -> Result<()> {
    let usable = c.usable_bytes;
    match find_entry(c, dir_block, name)? {
        None => Err(VaultError::NotFound(name.to_owned())),
        Some((block_idx, entry_idx)) => {
            let plain = c.read_plaintext_block(block_idx)?;
            let mut db = DirBlock::from_bytes(&plain);
            f(&mut db.entries[entry_idx]);
            c.mark_block_dirty(block_idx, db.to_bytes(usable));
            Ok(())
        }
    }
}

/// Check whether a directory block (and its chain) has no non-free entries.
pub(crate) fn dir_is_empty(c: &mut VaultContainer, dir_block: u64) -> Result<bool> {
    let mut current = dir_block;
    loop {
        let plain = c.read_plaintext_block(current)?;
        let db = DirBlock::from_bytes(&plain);
        if db.entries.iter().any(|e| e.entry_type != ENTRY_FREE) {
            return Ok(false);
        }
        if db.next_dir_block == u64::MAX {
            break;
        }
        current = db.next_dir_block;
    }
    Ok(true)
}

/// Collect all continuation blocks (not including `dir_block` itself).
pub(crate) fn collect_continuation_blocks(
    c: &mut VaultContainer,
    dir_block: u64,
) -> Result<Vec<u64>> {
    let mut result = Vec::new();
    let mut current = dir_block;
    loop {
        let plain = c.read_plaintext_block(current)?;
        let db = DirBlock::from_bytes(&plain);
        if db.next_dir_block == u64::MAX {
            break;
        }
        result.push(db.next_dir_block);
        current = db.next_dir_block;
    }
    Ok(result)
}
