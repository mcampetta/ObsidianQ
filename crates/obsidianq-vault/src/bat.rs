//! Block Allocation Table — in-memory bit array, one bit per data block.
//!
//! One 64 KiB BAT block holds 65520 bytes of payload = 524,160 bits,
//! covering 524,160 data blocks ≈ 32 GiB at 64 KiB / block.
//!
//! For v1, `bat_block_count` is always 1.

use crate::{Result, VaultError};

/// Maximum blocks tracked by a single BAT block (65520 × 8).
pub const BITS_PER_BAT_BLOCK: u64 = 65520 * 8; // 524_160

/// In-memory Block Allocation Table.
///
/// Bit `i` = 1 means data block `i` is allocated.
/// Bit 0 = BAT block itself (always 1).
/// Bit 1 = root DirBlock (always 1 after create).
pub struct BlockAllocationTable {
    /// Raw bit array (65520 bytes = 524 160 bits).
    data: Vec<u8>,
    /// Set to true when bits were modified since last flush.
    dirty: bool,
}

impl BlockAllocationTable {
    // ------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------

    /// Create a fresh BAT with blocks 0 (BAT) and 1 (root dir) marked used.
    pub fn new(usable_bytes: usize) -> Self {
        let mut bat = Self {
            data: vec![0u8; usable_bytes],
            dirty: true,
        };
        bat.mark_used(0); // BAT block
        bat.mark_used(1); // root dir block
        bat
    }

    /// Deserialize from the plaintext of a BAT block (length = usable_bytes).
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            dirty: false,
        }
    }

    // ------------------------------------------------------------------
    // Serialization
    // ------------------------------------------------------------------

    /// Borrow the raw bit array for encryption + writing.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    // ------------------------------------------------------------------
    // Bit operations
    // ------------------------------------------------------------------

    #[inline]
    pub fn is_used(&self, idx: u64) -> bool {
        let byte = (idx / 8) as usize;
        let bit = (idx % 8) as u32;
        byte < self.data.len() && (self.data[byte] >> bit) & 1 == 1
    }

    #[inline]
    fn mark_used(&mut self, idx: u64) {
        let byte = (idx / 8) as usize;
        let bit = (idx % 8) as u32;
        if byte < self.data.len() {
            self.data[byte] |= 1u8 << bit;
            self.dirty = true;
        }
    }

    #[inline]
    pub fn mark_free(&mut self, idx: u64) {
        let byte = (idx / 8) as usize;
        let bit = (idx % 8) as u32;
        if byte < self.data.len() {
            self.data[byte] &= !(1u8 << bit);
            self.dirty = true;
        }
    }

    // ------------------------------------------------------------------
    // Allocation / free
    // ------------------------------------------------------------------

    /// Allocate the next free block.
    ///
    /// Searches the range `[1, total_block_count)` for a free bit.
    /// If the range is fully used, grows the vault by one block.
    /// `total_block_count` is updated when the vault must grow.
    pub fn alloc(&mut self, total_block_count: &mut u64) -> Result<u64> {
        // Fast scan: byte by byte in the existing allocated range.
        let max_byte = (total_block_count.saturating_sub(1) / 8) as usize;
        'outer: for byte_idx in 0..=max_byte.min(self.data.len().saturating_sub(1)) {
            let byte = self.data[byte_idx];
            if byte == 0xFF {
                continue;
            } // all bits used in this byte

            for bit in 0u32..8u32 {
                let global_idx = byte_idx as u64 * 8 + bit as u64;
                if global_idx == 0 {
                    continue;
                } // skip BAT block
                if global_idx >= *total_block_count {
                    break 'outer;
                }
                if (byte >> bit) & 1 == 0 {
                    self.data[byte_idx] |= 1u8 << bit;
                    self.dirty = true;
                    return Ok(global_idx);
                }
            }
        }

        // No free block in existing range — grow the vault file.
        let new_idx = *total_block_count;
        if new_idx >= BITS_PER_BAT_BLOCK {
            return Err(VaultError::OutOfSpace);
        }
        *total_block_count += 1;
        self.mark_used(new_idx);
        Ok(new_idx)
    }

    /// Free a previously allocated block.
    pub fn free(&mut self, idx: u64) {
        debug_assert!(idx != 0, "cannot free BAT block 0");
        self.mark_free(idx);
    }

    // ------------------------------------------------------------------
    // Stats
    // ------------------------------------------------------------------

    /// Number of free blocks within `[1, total_block_count)`.
    pub fn free_block_count_in(&self, total_block_count: u64) -> u64 {
        (1..total_block_count).filter(|&i| !self.is_used(i)).count() as u64
    }

    // ------------------------------------------------------------------
    // Dirty tracking
    // ------------------------------------------------------------------

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }
}
