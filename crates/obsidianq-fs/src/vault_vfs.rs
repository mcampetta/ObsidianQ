//! R/W WinFSP virtual filesystem for ObsidianQ native vaults (`.vault`).
//!
//! SAFETY NOTES:
//! - `ObsqVaultFs` is pinned in a `Box` before its raw pointer is given to WinFSP.
//!   The Box is kept alive for the lifetime of the mount.
//! - FileContext is a `u64` handle ID (starting from 1) cast to PVOID — no heap
//!   allocation, no free, no pointer corruption possible.
//! - All `VaultContainer` access is serialized via `Mutex<VaultState>`.
//!   WinFSP's multi-threaded dispatcher is thereby serialized; acceptable for v1.

#![allow(non_snake_case)]

use std::collections::HashMap;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use obsidianq_core::crypto::kdf::MasterKey;
use obsidianq_vault::{VaultContainer, VaultError, VaultFileHandle};

use crate::error::{FsError, Result};
use crate::ffi::*;

// ---------------------------------------------------------------------------
// File-based VFS logger
//
// Writes one line per callback entry/exit and flushes immediately so the file
// survives crashes and is useful even when the mount process is still running.
// stderr is unreliable when stdout+stderr are redirected because WinFSP
// dispatcher threads buffer their output until process exit.
// ---------------------------------------------------------------------------

pub(crate) struct VfsLog {
    file: Mutex<std::fs::File>,
    start: std::time::Instant,
}

impl VfsLog {
    fn open(path: &Path) -> std::io::Result<Arc<Self>> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Arc::new(VfsLog {
            file: Mutex::new(f),
            start: std::time::Instant::now(),
        }))
    }

    pub(crate) fn write(&self, msg: &str) {
        use std::io::Write as _;
        let ms = self.start.elapsed().as_millis();
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "[+{ms:6}ms] {msg}");
            let _ = f.flush();
        }
    }
}

/// Write a log line if a VfsLog is present. Usage: `vlog!(log_opt, "fmt {}", args)`.
macro_rules! vlog {
    ($log:expr, $($arg:tt)*) => {
        if let Some(ref __l) = $log { __l.write(&format!($($arg)*)); }
    };
}

static GLOBAL_CB_LOG: OnceLock<Arc<VfsLog>> = OnceLock::new();

fn init_global_cb_log(path: Option<&Path>) {
    let Some(path) = path else { return };
    if GLOBAL_CB_LOG.get().is_some() {
        return;
    }
    if let Ok(log) = VfsLog::open(path) {
        let _ = GLOBAL_CB_LOG.set(log);
    }
}

fn write_global_cb_line(msg: &str) {
    if let Some(log) = GLOBAL_CB_LOG.get() {
        log.write(msg);
    }
}

macro_rules! log_cb_line {
    ($($arg:tt)*) => {
        write_global_cb_line(&format!($($arg)*));
    };
}

fn user_context_ptr(fsp: *mut FspFileSystem) -> usize {
    if fsp.is_null() {
        0
    } else {
        unsafe { FspFileSystemGetUserContext(fsp) as usize }
    }
}

// ---------------------------------------------------------------------------
// Additional NTSTATUS codes not defined in ffi.rs
// ---------------------------------------------------------------------------
const STATUS_DIRECTORY_NOT_EMPTY: NTSTATUS = 0xC0000101;
const STATUS_OBJECT_NAME_COLLISION: NTSTATUS = 0xC0000035;
const STATUS_FILE_IS_A_DIRECTORY: NTSTATUS = 0xC00000BA;
const STATUS_DISK_FULL: NTSTATUS = 0xC000007F;

/// WinFSP Cleanup flag: the file is being deleted.
const FSP_CLEANUP_DELETE: UINT32 = 0x01;

/// Maximum blocks one BAT block can track: (65536-16)*8 = 524,160 ≈ 32 GiB.
/// Reported as the volume's total/free size so Windows sees realistic capacity
/// rather than the current on-disk footprint.
const BAT_CAPACITY_BLOCKS: u64 = (65536 - 16) * 8;

/// CreateOptions flag that indicates directory creation.
const FILE_DIRECTORY_FILE: UINT32 = 0x00000001;

/// Windows HIDDEN file attribute flag.
const FILE_ATTRIBUTE_HIDDEN: UINT32 = 0x00000002;

// ---------------------------------------------------------------------------
// Handle + state types
// ---------------------------------------------------------------------------

struct OpenHandle {
    handle: VaultFileHandle,
    delete_on_close: bool,
}

struct VaultState {
    vault: VaultContainer,
    handles: HashMap<u64, OpenHandle>,
    next_id: u64,
}

impl VaultState {
    /// Allocate a stable handle ID (≥ 1) and register the handle.
    fn alloc_handle(&mut self, vh: VaultFileHandle) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.handles.insert(
            id,
            OpenHandle {
                handle: vh,
                delete_on_close: false,
            },
        );
        id
    }

    fn usable(&self) -> u64 {
        self.vault.block_usable_bytes()
    }
}

// ---------------------------------------------------------------------------
// Filesystem object (one instance per mount)
// ---------------------------------------------------------------------------

pub struct ObsqVaultFs {
    state: Arc<Mutex<VaultState>>,
    log: Option<Arc<VfsLog>>,
}

// SAFETY: VaultState is Send + Sync because VaultContainer contains
// a File (Send) wrapped in Mutex.  The Mutex makes it Sync.
unsafe impl Send for ObsqVaultFs {}
unsafe impl Sync for ObsqVaultFs {}

// ---------------------------------------------------------------------------
// Path helper
// ---------------------------------------------------------------------------

/// Convert a WinFSP PWSTR (backslash-separated) to a vault path (forward slashes).
fn wpath_to_vault(raw: PWSTR) -> String {
    let s = unsafe { wchar_to_string(raw) };
    if s.is_empty() || s == "\\" {
        "/".to_string()
    } else {
        s.replace('\\', "/")
    }
}

// ---------------------------------------------------------------------------
// Attribute conversion helpers
// ---------------------------------------------------------------------------

fn vault_attr_to_windows(attr: u8, is_dir: bool) -> UINT32 {
    let mut fa: UINT32 = 0;
    if is_dir {
        fa |= FILE_ATTRIBUTE_DIRECTORY;
    }
    // attr bit 0 was "hidden" — inside an encrypted vault, files are always
    // visible to the owner; we do not propagate HIDDEN to the WinFSP view.
    if attr & 2 != 0 {
        fa |= FILE_ATTRIBUTE_READONLY;
    }
    if fa == 0 {
        fa = FILE_ATTRIBUTE_NORMAL;
    }
    fa
}

fn windows_attr_to_vault(fa: UINT32) -> u8 {
    let mut attr: u8 = 0;
    if fa & FILE_ATTRIBUTE_HIDDEN != 0 {
        attr |= 1;
    }
    if fa & FILE_ATTRIBUTE_READONLY != 0 {
        attr |= 2;
    }
    attr
}

// ---------------------------------------------------------------------------
// Build FspFsctlFileInfo from a VaultFileHandle
// ---------------------------------------------------------------------------

fn handle_to_file_info(h: &VaultFileHandle, usable: u64) -> FspFsctlFileInfo {
    let size = if h.is_dir { 0 } else { h.size };
    let alloc = if h.is_dir || size == 0 {
        0
    } else {
        ((size + usable - 1) / usable) * usable
    };
    FspFsctlFileInfo {
        FileAttributes: vault_attr_to_windows(h.attr, h.is_dir),
        ReparseTag: 0,
        AllocationSize: alloc,
        FileSize: size,
        CreationTime: h.created,
        LastAccessTime: h.accessed,
        LastWriteTime: h.modified,
        ChangeTime: h.modified,
        IndexNumber: 0,
        HardLinks: 1,
        EaSize: 0,
    }
}

// ---------------------------------------------------------------------------
// VaultError → NTSTATUS
// ---------------------------------------------------------------------------

fn vault_err_to_ntstatus(e: &VaultError) -> NTSTATUS {
    match e {
        VaultError::NotFound(_) => STATUS_OBJECT_NAME_NOT_FOUND,
        VaultError::AlreadyExists(_) => STATUS_OBJECT_NAME_COLLISION,
        VaultError::NotADirectory(_) => STATUS_NOT_A_DIRECTORY,
        VaultError::IsADirectory(_) => STATUS_FILE_IS_A_DIRECTORY,
        VaultError::DirectoryNotEmpty(_) => STATUS_DIRECTORY_NOT_EMPTY,
        VaultError::OutOfSpace | VaultError::FileTooLarge => STATUS_DISK_FULL,
        _ => STATUS_ACCESS_DENIED,
    }
}

// ---------------------------------------------------------------------------
// Get &ObsqVaultFs from WinFSP UserContext
// ---------------------------------------------------------------------------

unsafe fn get_fs<'a>(fsp: *mut FspFileSystem) -> &'a ObsqVaultFs {
    let ptr = unsafe { FspFileSystemGetUserContext(fsp) } as *const ObsqVaultFs;
    unsafe { &*ptr }
}

// ---------------------------------------------------------------------------
// Callback: GetVolumeInfo
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_get_volume_info(
    fsp: *mut FspFileSystem,
    info: *mut FspFsctlVolumeInfo,
) -> NTSTATUS {
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.GetVolumeInfo ctx=0x{ctx:016X} ctx_null={} info_null={}",
        ctx == 0,
        info.is_null()
    );
    if fsp.is_null() || info.is_null() {
        log_cb_line!(
            "EXIT  VFS.GetVolumeInfo status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.GetVolumeInfo status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_fs(fsp) }.log;
    eprintln!("[VFS] GetVolumeInfo");
    vlog!(log, "CALL GetVolumeInfo");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let st = fs.state.lock().unwrap();
        let usable = st.usable();
        // Report the BAT's maximum capacity (≈ 32 GiB) rather than the
        // current on-disk footprint.  Auto-grow vaults start with only 2
        // allocated blocks; reporting that as total/free would make Windows
        // refuse every file copy with "not enough space".
        let used = st.vault.total_blocks();
        let total = BAT_CAPACITY_BLOCKS * usable;
        let free = BAT_CAPACITY_BLOCKS.saturating_sub(used) * usable;
        let out = unsafe { &mut *info };
        out.TotalSize = total;
        out.FreeSize = free;
        out.VolumeLabelLength = ("ObsidianQV".encode_utf16().count() * 2) as UINT16;
        str_to_wchar_fixed("ObsidianQV", &mut out.VolumeLabel);
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_get_volume_info");
        STATUS_ACCESS_DENIED
    });
    eprintln!("[VFS] GetVolumeInfo -> {:#010x}", r);
    log_cb_line!("EXIT  VFS.GetVolumeInfo status={r:#010x}");
    vlog!(log, "RETN GetVolumeInfo -> {r:#010x}");
    r
}

// ---------------------------------------------------------------------------
// Callback: GetSecurityByName
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_get_security_by_name(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    p_file_attrs: *mut UINT32,
    _sec_desc: PVOID,
    sec_size: PSIZE_T,
) -> NTSTATUS {
    let path = wpath_to_vault(file_name);
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.GetSecurityByName ctx=0x{ctx:016X} ctx_null={} path={:?}",
        ctx == 0,
        path
    );
    if fsp.is_null() || file_name.is_null() {
        eprintln!("[VFS] GetSecurityByName {:?} -> INVALID_PARAM", path);
        log_cb_line!(
            "EXIT  VFS.GetSecurityByName path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.GetSecurityByName path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_fs(fsp) }.log;
    eprintln!("[VFS] GetSecurityByName {:?}", path);
    vlog!(log, "CALL GetSecurityByName path={:?}", path);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if !sec_size.is_null() {
            unsafe {
                *sec_size = 0;
            }
        }
        let fs = unsafe { get_fs(fsp) };
        let mut st = fs.state.lock().unwrap();
        match st.vault.stat(&path) {
            Ok(info) => {
                if !p_file_attrs.is_null() {
                    unsafe {
                        *p_file_attrs = vault_attr_to_windows(info.attr, info.is_dir);
                    }
                }
                STATUS_SUCCESS
            }
            Err(VaultError::NotFound(_)) => STATUS_OBJECT_NAME_NOT_FOUND,
            Err(e) => vault_err_to_ntstatus(&e),
        }
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_get_security_by_name");
        STATUS_ACCESS_DENIED
    });
    eprintln!("[VFS] GetSecurityByName {:?} -> {:#010x}", path, r);
    log_cb_line!(
        "EXIT  VFS.GetSecurityByName path={:?} status={r:#010x}",
        path
    );
    vlog!(log, "RETN GetSecurityByName path={:?} -> {r:#010x}", path);
    r
}

// ---------------------------------------------------------------------------
// Callback: Create
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_create(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    create_opts: UINT32,
    _granted: UINT32,
    file_attrs: UINT32,
    _sec_desc: PVOID,
    _alloc_size: UINT64,
    p_fc: *mut PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let path = wpath_to_vault(file_name);
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.Create ctx=0x{ctx:016X} ctx_null={} path={:?}",
        ctx == 0,
        path
    );
    if fsp.is_null() || file_name.is_null() || p_fc.is_null() || p_info.is_null() {
        log_cb_line!(
            "EXIT  VFS.Create path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.Create path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let is_dir = (create_opts & FILE_DIRECTORY_FILE) != 0;
        let mut st = fs.state.lock().unwrap();

        let res = if is_dir {
            st.vault.create_dir(&path)
        } else {
            st.vault.create_file(&path)
        };
        if let Err(e) = res {
            return vault_err_to_ntstatus(&e);
        }

        // Apply initial file attributes.
        let attr = windows_attr_to_vault(file_attrs);
        if attr != 0 {
            let _ = st.vault.set_attr(&path, attr);
        }

        let vh = match st.vault.open_handle(&path) {
            Ok(v) => v,
            Err(e) => return vault_err_to_ntstatus(&e),
        };
        let usable = st.usable();
        let fi = handle_to_file_info(&vh, usable);
        let id = st.alloc_handle(vh);
        unsafe {
            *p_fc = id as usize as PVOID;
        }
        unsafe {
            *p_info = fi;
        }
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_create");
        STATUS_ACCESS_DENIED
    });
    log_cb_line!("EXIT  VFS.Create path={:?} status={r:#010x}", path);
    r
}

unsafe extern "system" fn cb_create_ex(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    create_opts: UINT32,
    granted: UINT32,
    file_attrs: UINT32,
    sec_desc: PVOID,
    alloc_size: UINT64,
    _extra: PVOID,
    _extra_len: ULONG,
    _extra_is_rp: BOOLEAN,
    p_fc: *mut PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let path = wpath_to_vault(file_name);
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.CreateEx ctx=0x{ctx:016X} ctx_null={} path={:?}",
        ctx == 0,
        path
    );
    let r = cb_create(
        fsp,
        file_name,
        create_opts,
        granted,
        file_attrs,
        sec_desc,
        alloc_size,
        p_fc,
        p_info,
    );
    log_cb_line!("EXIT  VFS.CreateEx path={:?} status={r:#010x}", path);
    r
}

// ---------------------------------------------------------------------------
// Callback: Open
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_open(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    _opts: UINT32,
    _granted: UINT32,
    p_fc: *mut PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let path = wpath_to_vault(file_name);
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.Open ctx=0x{ctx:016X} ctx_null={} path={:?}",
        ctx == 0,
        path
    );
    if fsp.is_null() || file_name.is_null() || p_fc.is_null() || p_info.is_null() {
        eprintln!("[VFS] Open {:?} -> INVALID_PARAM", path);
        log_cb_line!(
            "EXIT  VFS.Open path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.Open path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_fs(fsp) }.log;
    eprintln!("[VFS] Open {:?}", path);
    vlog!(log, "CALL Open path={:?}", path);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let mut st = fs.state.lock().unwrap();
        let vh = match st.vault.open_handle(&path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[VFS] Open {:?} error: {e}", path);
                return vault_err_to_ntstatus(&e);
            }
        };
        let usable = st.usable();
        let fi = handle_to_file_info(&vh, usable);
        let id = st.alloc_handle(vh);
        unsafe {
            *p_fc = id as usize as PVOID;
        }
        unsafe {
            *p_info = fi;
        }
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_open");
        STATUS_ACCESS_DENIED
    });
    eprintln!("[VFS] Open {:?} -> {:#010x}", path, r);
    log_cb_line!("EXIT  VFS.Open path={:?} status={r:#010x}", path);
    vlog!(log, "RETN Open path={:?} -> {r:#010x}", path);
    r
}

// ---------------------------------------------------------------------------
// Callback: Overwrite (truncate to 0 then open)
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_overwrite(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _file_attr: UINT32,
    _replace: BOOLEAN,
    _alloc: UINT64,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    if fsp.is_null() || p_info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let id = fc as u64;
        let mut st = fs.state.lock().unwrap();

        // Extract path and state; release borrow before calling vault.
        let (path, mut block_map, mut size, usable) = {
            let oh = match st.handles.get(&id) {
                Some(h) => h,
                None => return STATUS_OBJECT_NAME_NOT_FOUND,
            };
            (
                oh.handle.path.clone(),
                oh.handle.block_map.clone(),
                oh.handle.size,
                st.usable(),
            )
        };

        if let Err(e) = st.vault.set_size(&path, &mut block_map, &mut size, 0) {
            return vault_err_to_ntstatus(&e);
        }

        let oh = st.handles.get_mut(&id).unwrap();
        oh.handle.block_map = block_map;
        oh.handle.size = size;
        unsafe {
            *p_info = handle_to_file_info(&oh.handle, usable);
        }
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_overwrite");
        STATUS_ACCESS_DENIED
    })
}

// ---------------------------------------------------------------------------
// Callback: Cleanup
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_cleanup(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _filename: PWSTR,
    flags: UINT32,
) {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.Cleanup ctx=0x{ctx:016X} ctx_null={} handle={id} flags={flags:#x}",
        ctx == 0
    );
    if fsp.is_null() || ctx == 0 {
        log_cb_line!("EXIT  VFS.Cleanup handle={id}");
        return;
    }
    let log = &unsafe { get_fs(fsp) }.log;
    eprintln!("[VFS] Cleanup handle={} flags={:#x}", id, flags);
    vlog!(log, "CALL Cleanup handle={id} flags={flags:#x}");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if (flags & FSP_CLEANUP_DELETE) == 0 {
            return;
        }
        let fs = unsafe { get_fs(fsp) };
        let mut st = fs.state.lock().unwrap();
        if let Some(oh) = st.handles.get_mut(&id) {
            oh.delete_on_close = true;
        }
    }));
    log_cb_line!("EXIT  VFS.Cleanup handle={id}");
}

// ---------------------------------------------------------------------------
// Callback: Close
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_close(fsp: *mut FspFileSystem, fc: PVOID) {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.Close ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() || ctx == 0 {
        log_cb_line!("EXIT  VFS.Close handle={id}");
        return;
    }
    let log = &unsafe { get_fs(fsp) }.log;
    eprintln!("[VFS] Close handle={}", id);
    vlog!(log, "CALL Close handle={id}");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let id = fc as u64;
        let mut st = fs.state.lock().unwrap();
        if let Some(oh) = st.handles.remove(&id) {
            if oh.delete_on_close {
                let path = oh.handle.path.clone();
                let res = if oh.handle.is_dir {
                    st.vault.remove_dir(&path)
                } else {
                    st.vault.delete_file(&path)
                };
                if res.is_ok() {
                    if let Err(e) = st.vault.flush() {
                        eprintln!("[obsidianq-fs] vault flush (delete-close) error: {e}");
                    }
                }
            } else if !oh.handle.is_dir && st.vault.has_dirty_blocks() {
                // Commit any pending writes when the file is closed normally.
                // WinFSP does not always call Flush before Close (Explorer in
                // particular skips it), so we flush here to ensure directory
                // entries and data blocks are persisted.
                if let Err(e) = st.vault.flush() {
                    eprintln!("[obsidianq-fs] vault flush (file-close) error: {e}");
                }
            }
        }
    }));
    log_cb_line!("EXIT  VFS.Close handle={id}");
}

// ---------------------------------------------------------------------------
// Callback: Read
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_read(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    buffer: PVOID,
    offset: UINT64,
    length: ULONG,
    p_bt: PULONG,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.Read ctx=0x{ctx:016X} ctx_null={} handle={id} offset={offset} len={length}",
        ctx == 0
    );
    if fsp.is_null() || p_bt.is_null() {
        log_cb_line!(
            "EXIT  VFS.Read handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.Read handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        *p_bt = 0;
    }
    if buffer.is_null() && length != 0 {
        log_cb_line!(
            "EXIT  VFS.Read handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if length == 0 {
        log_cb_line!("EXIT  VFS.Read handle={id} status={:#010x}", STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let id = fc as u64;
        let mut st = fs.state.lock().unwrap();

        let (block_map, size) = {
            let oh = match st.handles.get(&id) {
                Some(h) => h,
                None => return STATUS_OBJECT_NAME_NOT_FOUND,
            };
            if oh.handle.is_dir {
                return STATUS_NOT_A_DIRECTORY;
            }
            (oh.handle.block_map.clone(), oh.handle.size)
        };

        if offset >= size {
            return STATUS_END_OF_FILE;
        }
        let buf = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, length as usize) };
        match st.vault.read_range(&block_map, size, offset, buf) {
            Ok(n) => {
                unsafe {
                    *p_bt = n as ULONG;
                }
                if n == 0 {
                    STATUS_END_OF_FILE
                } else {
                    STATUS_SUCCESS
                }
            }
            Err(e) => {
                eprintln!("[obsidianq-fs] vault read error at offset {offset}: {e}");
                STATUS_ACCESS_DENIED
            }
        }
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_read offset={offset} len={length}");
        STATUS_ACCESS_DENIED
    });
    log_cb_line!("EXIT  VFS.Read handle={id} status={r:#010x}");
    r
}

// ---------------------------------------------------------------------------
// Callback: Write
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_write(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    buffer: PVOID,
    offset: UINT64,
    length: ULONG,
    write_to_eof: BOOLEAN,
    _constrained: BOOLEAN,
    p_bt: PULONG,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    if fsp.is_null() || p_bt.is_null() || p_info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        *p_bt = 0;
    }
    if buffer.is_null() && length != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if length == 0 {
        return STATUS_SUCCESS;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let id = fc as u64;
        let mut st = fs.state.lock().unwrap();

        let (path, mut block_map, mut size, usable) = {
            let oh = match st.handles.get(&id) {
                Some(h) => h,
                None => return STATUS_OBJECT_NAME_NOT_FOUND,
            };
            if oh.handle.is_dir {
                return STATUS_NOT_A_DIRECTORY;
            }
            (
                oh.handle.path.clone(),
                oh.handle.block_map.clone(),
                oh.handle.size,
                st.usable(),
            )
        };

        let actual_offset = if write_to_eof != 0 { size } else { offset };
        let data = unsafe { std::slice::from_raw_parts(buffer as *const u8, length as usize) };
        if let Err(e) = st
            .vault
            .write_range(&path, &mut block_map, &mut size, actual_offset, data)
        {
            return vault_err_to_ntstatus(&e);
        }

        let oh = st.handles.get_mut(&id).unwrap();
        oh.handle.block_map = block_map;
        oh.handle.size = size;
        unsafe {
            *p_bt = length;
            *p_info = handle_to_file_info(&oh.handle, usable);
        }
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_write");
        STATUS_ACCESS_DENIED
    })
}

// ---------------------------------------------------------------------------
// Callback: Flush
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_flush(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.Flush ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() || ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.Flush handle={id} status={:#010x}",
            STATUS_SUCCESS
        );
        return STATUS_SUCCESS;
    }
    let log = &unsafe { get_fs(fsp) }.log;
    eprintln!("[VFS] Flush handle={}", id);
    vlog!(log, "CALL Flush handle={id}");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let mut st = fs.state.lock().unwrap();
        if let Err(e) = st.vault.flush() {
            eprintln!("[obsidianq-fs] vault flush error: {e}");
            return STATUS_ACCESS_DENIED;
        }
        // Return file info for the flushed handle (if given).
        if !fc.is_null() && !p_info.is_null() {
            let id = fc as u64;
            let usable = st.usable();
            if let Some(oh) = st.handles.get(&id) {
                unsafe {
                    *p_info = handle_to_file_info(&oh.handle, usable);
                }
            }
        }
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_flush");
        STATUS_ACCESS_DENIED
    });
    eprintln!("[VFS] Flush handle={} -> {:#010x}", id, r);
    log_cb_line!("EXIT  VFS.Flush handle={id} status={r:#010x}");
    vlog!(log, "RETN Flush handle={id} -> {r:#010x}");
    r
}

// ---------------------------------------------------------------------------
// Callback: GetFileInfo
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_get_file_info(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.GetFileInfo ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() || p_info.is_null() {
        log_cb_line!(
            "EXIT  VFS.GetFileInfo handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.GetFileInfo handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_fs(fsp) }.log;
    eprintln!("[VFS] GetFileInfo handle={}", id);
    vlog!(log, "CALL GetFileInfo handle={id}");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let st = fs.state.lock().unwrap();
        match st.handles.get(&id) {
            Some(oh) => {
                unsafe {
                    *p_info = handle_to_file_info(&oh.handle, st.usable());
                }
                STATUS_SUCCESS
            }
            None => STATUS_OBJECT_NAME_NOT_FOUND,
        }
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_get_file_info");
        STATUS_ACCESS_DENIED
    });
    eprintln!("[VFS] GetFileInfo handle={} -> {:#010x}", id, r);
    log_cb_line!("EXIT  VFS.GetFileInfo handle={id} status={r:#010x}");
    vlog!(log, "RETN GetFileInfo handle={id} -> {r:#010x}");
    r
}

// ---------------------------------------------------------------------------
// Callback: SetBasicInfo (timestamps + attributes)
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_set_basic_info(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    fa: UINT32,
    ctime: UINT64,
    atime: UINT64,
    mtime: UINT64,
    _chgtime: UINT64,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.SetBasicInfo ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() || p_info.is_null() {
        log_cb_line!(
            "EXIT  VFS.SetBasicInfo handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.SetBasicInfo handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let id = fc as u64;
        let mut st = fs.state.lock().unwrap();

        let (path, is_dir, usable) = {
            let oh = match st.handles.get(&id) {
                Some(h) => h,
                None => return STATUS_OBJECT_NAME_NOT_FOUND,
            };
            (oh.handle.path.clone(), oh.handle.is_dir, st.usable())
        };

        // Persist to vault dirty cache.
        if path != "/" && (ctime != 0 || mtime != 0 || atime != 0) {
            if let Err(e) = st.vault.set_times(&path, ctime, mtime, atime) {
                return vault_err_to_ntstatus(&e);
            }
        }
        if !is_dir && fa != 0 {
            let attr = windows_attr_to_vault(fa);
            if let Err(e) = st.vault.set_attr(&path, attr) {
                return vault_err_to_ntstatus(&e);
            }
        }

        // Update cached handle values in place (avoids re-reading block_map).
        let oh = st.handles.get_mut(&id).unwrap();
        if ctime != 0 {
            oh.handle.created = ctime;
        }
        if mtime != 0 {
            oh.handle.modified = mtime;
        }
        if atime != 0 {
            oh.handle.accessed = atime;
        }
        if !is_dir && fa != 0 {
            oh.handle.attr = windows_attr_to_vault(fa);
        }
        unsafe {
            *p_info = handle_to_file_info(&oh.handle, usable);
        }
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_set_basic_info");
        STATUS_ACCESS_DENIED
    });
    log_cb_line!("EXIT  VFS.SetBasicInfo handle={id} status={r:#010x}");
    r
}

// ---------------------------------------------------------------------------
// Callback: SetFileSize
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_set_file_size(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    new_size: UINT64,
    set_alloc_size: BOOLEAN,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    if fsp.is_null() || p_info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let id = fc as u64;
        let mut st = fs.state.lock().unwrap();

        // Allocation-size hints don't need to change the file size.
        if set_alloc_size != 0 {
            let usable = st.usable();
            return match st.handles.get(&id) {
                Some(oh) => {
                    unsafe {
                        *p_info = handle_to_file_info(&oh.handle, usable);
                    }
                    STATUS_SUCCESS
                }
                None => STATUS_OBJECT_NAME_NOT_FOUND,
            };
        }

        let (path, mut block_map, mut size, usable) = {
            let oh = match st.handles.get(&id) {
                Some(h) => h,
                None => return STATUS_OBJECT_NAME_NOT_FOUND,
            };
            (
                oh.handle.path.clone(),
                oh.handle.block_map.clone(),
                oh.handle.size,
                st.usable(),
            )
        };

        if let Err(e) = st
            .vault
            .set_size(&path, &mut block_map, &mut size, new_size)
        {
            return vault_err_to_ntstatus(&e);
        }

        let oh = st.handles.get_mut(&id).unwrap();
        oh.handle.block_map = block_map;
        oh.handle.size = size;
        unsafe {
            *p_info = handle_to_file_info(&oh.handle, usable);
        }
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_set_file_size");
        STATUS_ACCESS_DENIED
    })
}

// ---------------------------------------------------------------------------
// Callback: CanDelete
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_can_delete(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _filename: PWSTR,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.CanDelete ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() {
        log_cb_line!(
            "EXIT  VFS.CanDelete handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.CanDelete handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let id = fc as u64;
        let mut st = fs.state.lock().unwrap();
        let (path, is_dir) = match st.handles.get(&id) {
            Some(h) => (h.handle.path.clone(), h.handle.is_dir),
            None => return STATUS_OBJECT_NAME_NOT_FOUND,
        };
        if is_dir {
            // Reject if directory has children.
            match st.vault.list_dir(&path) {
                Ok(entries) if !entries.is_empty() => STATUS_DIRECTORY_NOT_EMPTY,
                Ok(_) => STATUS_SUCCESS,
                Err(e) => vault_err_to_ntstatus(&e),
            }
        } else {
            STATUS_SUCCESS
        }
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_can_delete");
        STATUS_ACCESS_DENIED
    });
    log_cb_line!("EXIT  VFS.CanDelete handle={id} status={r:#010x}");
    r
}

// ---------------------------------------------------------------------------
// Callback: Rename
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_rename(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _file_name: PWSTR,
    new_file_name: PWSTR,
    _replace: BOOLEAN,
) -> NTSTATUS {
    if fsp.is_null() || new_file_name.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let id = fc as u64;
        let new_path = wpath_to_vault(new_file_name);
        let mut st = fs.state.lock().unwrap();
        let old_path = match st.handles.get(&id) {
            Some(h) => h.handle.path.clone(),
            None => return STATUS_OBJECT_NAME_NOT_FOUND,
        };
        if let Err(e) = st.vault.rename(&old_path, &new_path) {
            return vault_err_to_ntstatus(&e);
        }
        // Update cached path in this handle.
        if let Some(oh) = st.handles.get_mut(&id) {
            oh.handle.path = new_path;
        }
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_rename");
        STATUS_ACCESS_DENIED
    })
}

// ---------------------------------------------------------------------------
// Callback: GetSecurity / SetSecurity (null security model)
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_get_security(
    _fsp: *mut FspFileSystem,
    _fc: PVOID,
    _sec: PVOID,
    sec_size: PSIZE_T,
) -> NTSTATUS {
    if !sec_size.is_null() {
        unsafe {
            *sec_size = 0;
        }
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn cb_set_security(
    _fsp: *mut FspFileSystem,
    _fc: PVOID,
    _sec_info: UINT32,
    _sec_desc: PVOID,
) -> NTSTATUS {
    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Callback: ReadDirectory
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_read_directory(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _pat: PWSTR,
    marker: PWSTR,
    buffer: PVOID,
    length: ULONG,
    p_bt: PULONG,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.ReadDirectory ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() || p_bt.is_null() {
        log_cb_line!(
            "EXIT  VFS.ReadDirectory handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.ReadDirectory handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        *p_bt = 0;
    }
    if buffer.is_null() && length != 0 {
        log_cb_line!(
            "EXIT  VFS.ReadDirectory handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_fs(fsp) }.log;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let mut st = fs.state.lock().unwrap();

        let (path, is_dir) = match st.handles.get(&id) {
            Some(h) => (h.handle.path.clone(), h.handle.is_dir),
            None => {
                eprintln!(
                    "[VFS] ReadDirectory handle={} NOT in map (handles: {:?})",
                    id,
                    st.handles.keys().collect::<Vec<_>>()
                );
                vlog!(log, "RETN ReadDirectory handle={id} -> NOT_IN_MAP");
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
        };
        let marker_dbg = if marker.is_null() {
            "<null>".to_string()
        } else {
            unsafe { wchar_to_string(marker) }
        };
        eprintln!(
            "[VFS] ReadDirectory {:?} handle={} marker={:?}",
            path, id, marker_dbg
        );
        vlog!(
            log,
            "CALL ReadDirectory path={:?} handle={id} marker={:?}",
            path,
            marker_dbg
        );
        if !is_dir {
            return STATUS_NOT_A_DIRECTORY;
        }

        // Build FspFsctlFileInfo for "." and ".." using directory metadata.
        let stat = match st.vault.stat(&path) {
            Ok(s) => s,
            Err(e) => return vault_err_to_ntstatus(&e),
        };
        let usable = st.usable();
        let dir_fi = FspFsctlFileInfo {
            FileAttributes: FILE_ATTRIBUTE_DIRECTORY,
            ReparseTag: 0,
            AllocationSize: 0,
            FileSize: 0,
            CreationTime: stat.created,
            LastAccessTime: stat.accessed,
            LastWriteTime: stat.modified,
            ChangeTime: stat.modified,
            IndexNumber: 0,
            HardLinks: 1,
            EaSize: 0,
        };

        // Collect and sort children for correct marker-based pagination.
        let mut entries = match st.vault.list_dir(&path) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[obsidianq-fs] ReadDirectory list_dir({path:?}) error: {e}");
                return vault_err_to_ntstatus(&e);
            }
        };
        entries.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
        });

        // Marker: skip entries whose name (lower-cased) is <= marker.
        let marker_str = if marker.is_null() {
            String::new()
        } else {
            unsafe { wchar_to_string(marker) }
        };
        let marker_lower = marker_str.to_ascii_lowercase();
        let is_past = |name: &str| -> bool {
            !marker_str.is_empty() && name.to_ascii_lowercase() <= marker_lower
        };

        // Macro: add one dir-info entry; stop and return if buffer is full.
        macro_rules! try_add {
            ($di:expr) => {{
                let ok = unsafe { FspFileSystemAddDirInfo($di, buffer, length, p_bt) };
                if ok == 0 {
                    log_cb_line!(
                        "EXIT  VFS.ReadDirectory handle={id} status={:#010x}",
                        STATUS_SUCCESS
                    );
                    return STATUS_SUCCESS;
                }
            }};
        }

        if !is_past(".") {
            let mut di = FspFsctlDirInfo::new(dir_fi, ".");
            try_add!(&mut di);
        }
        if !is_past("..") {
            let mut di = FspFsctlDirInfo::new(dir_fi, "..");
            try_add!(&mut di);
        }

        for info in &entries {
            if is_past(&info.name) {
                continue;
            }
            let size = if info.is_dir { 0 } else { info.size };
            let alloc = if size == 0 {
                0
            } else {
                ((size + usable - 1) / usable) * usable
            };
            let fi = FspFsctlFileInfo {
                FileAttributes: vault_attr_to_windows(info.attr, info.is_dir),
                ReparseTag: 0,
                AllocationSize: alloc,
                FileSize: size,
                CreationTime: info.created,
                LastAccessTime: info.accessed,
                LastWriteTime: info.modified,
                ChangeTime: info.modified,
                IndexNumber: 0,
                HardLinks: 1,
                EaSize: 0,
            };
            let mut di = FspFsctlDirInfo::new(fi, &info.name);
            try_add!(&mut di);
        }

        // Null entry = end of directory listing.
        eprintln!(
            "[VFS] ReadDirectory {:?} -> {} entr(ies) added",
            path,
            entries.len()
        );
        vlog!(
            log,
            "RETN ReadDirectory path={:?} entries={} -> {:#010x}",
            path,
            entries.len(),
            STATUS_SUCCESS
        );
        unsafe {
            FspFileSystemAddDirInfo(std::ptr::null_mut(), buffer, length, p_bt);
        }
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in vault cb_read_directory");
        vlog!(log, "RETN ReadDirectory handle={id} -> PANIC");
        STATUS_ACCESS_DENIED
    });
    log_cb_line!("EXIT  VFS.ReadDirectory handle={id} status={r:#010x}");
    r
}

unsafe extern "system" fn cb_get_dir_info_by_name(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    file_name: PWSTR,
    dir_info: *mut FspFsctlDirInfo,
) -> NTSTATUS {
    let id = fc as u64;
    let child = if file_name.is_null() {
        String::new()
    } else {
        unsafe { wchar_to_string(file_name) }
    };
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER VFS.GetDirInfoByName ctx=0x{ctx:016X} ctx_null={} handle={id} name={:?}",
        ctx == 0,
        child
    );
    if fsp.is_null() || file_name.is_null() || dir_info.is_null() {
        log_cb_line!(
            "EXIT  VFS.GetDirInfoByName handle={id} name={:?} status={:#010x}",
            child,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  VFS.GetDirInfoByName handle={id} name={:?} status={:#010x}",
            child,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let mut st = fs.state.lock().unwrap();
        let parent = match st.handles.get(&id) {
            Some(h) if h.handle.is_dir => h.handle.path.clone(),
            Some(_) => return STATUS_NOT_A_DIRECTORY,
            None => return STATUS_OBJECT_NAME_NOT_FOUND,
        };
        let full = if parent == "/" {
            format!("/{}", child)
        } else {
            format!("{}/{}", parent, child)
        };
        let info = match st.vault.stat(&full) {
            Ok(s) => s,
            Err(VaultError::NotFound(_)) => return STATUS_OBJECT_NAME_NOT_FOUND,
            Err(e) => return vault_err_to_ntstatus(&e),
        };
        let usable = st.usable();
        let size = if info.is_dir { 0 } else { info.size };
        let alloc = if size == 0 {
            0
        } else {
            ((size + usable - 1) / usable) * usable
        };
        let fi = FspFsctlFileInfo {
            FileAttributes: vault_attr_to_windows(info.attr, info.is_dir),
            ReparseTag: 0,
            AllocationSize: alloc,
            FileSize: size,
            CreationTime: info.created,
            LastAccessTime: info.accessed,
            LastWriteTime: info.modified,
            ChangeTime: info.modified,
            IndexNumber: 0,
            HardLinks: 1,
            EaSize: 0,
        };
        unsafe {
            *dir_info = FspFsctlDirInfo::new(fi, &child);
        }
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_ACCESS_DENIED);
    log_cb_line!(
        "EXIT  VFS.GetDirInfoByName handle={id} name={:?} status={r:#010x}",
        child
    );
    r
}

// ---------------------------------------------------------------------------
// Dispatcher-stopped notification (reuses the shared stop event handle)
// ---------------------------------------------------------------------------

unsafe extern "system" fn cb_dispatcher_stopped(_fsp: *mut FspFileSystem, normally: BOOLEAN) {
    if normally != 0 {
        eprintln!("[obsidianq-fs] vault dispatcher stopped normally.");
        return;
    }
    eprintln!("[obsidianq-fs] vault dispatcher stopped ABNORMALLY — signaling stop.");
    use std::sync::atomic::Ordering;
    let h =
        crate::STOP_EVENT_HANDLE.load(Ordering::Relaxed) as windows_sys::Win32::Foundation::HANDLE;
    if !h.is_null() {
        unsafe {
            windows_sys::Win32::System::Threading::SetEvent(h);
        }
    }
}

// ---------------------------------------------------------------------------
// Interface table (must be `static`; WinFSP holds a pointer to it)
// ---------------------------------------------------------------------------

static VAULT_INTERFACE: FspFileSystemInterface = FspFileSystemInterface {
    get_volume_info: Some(cb_get_volume_info),
    set_volume_label: None,
    get_security_by_name: Some(cb_get_security_by_name),
    create: Some(cb_create),
    open: Some(cb_open),
    overwrite: Some(cb_overwrite),
    cleanup: Some(cb_cleanup),
    close: Some(cb_close),
    read: Some(cb_read),
    write: Some(cb_write),
    flush: Some(cb_flush),
    get_file_info: Some(cb_get_file_info),
    set_basic_info: Some(cb_set_basic_info),
    set_file_size: Some(cb_set_file_size),
    can_delete: Some(cb_can_delete),
    rename: Some(cb_rename),
    get_security: Some(cb_get_security),
    set_security: Some(cb_set_security),
    read_directory: Some(cb_read_directory),
    resolve_reparse_points: None,
    get_reparse_point: None,
    set_reparse_point: None,
    delete_reparse_point: None,
    get_stream_info: None,
    get_dir_info_by_name: Some(cb_get_dir_info_by_name),
    control: None,
    set_delete: None,
    create_ex: Some(cb_create_ex),
    overwrite_ex: None,
    get_ea: None,
    set_ea: None,
    obsolete0: None,
    dispatcher_stopped: Some(cb_dispatcher_stopped),
    _rest: [0usize; 31],
};

// ---------------------------------------------------------------------------
// Public mount function
// ---------------------------------------------------------------------------

/// Mount a `.vault` vault as a read/write virtual drive at `drive_letter:`.
///
/// Blocks until `stop_event` is signalled (from `unmount_vault`) or Ctrl+C.
/// Flushes the vault before unmounting.
///
/// # Safety
/// Internally uses WinFSP FFI.  Safe to call from Rust.
pub fn mount_vault(
    vault_path: &Path,
    master_key: MasterKey,
    drive_letter: char,
    stop_event: windows_sys::Win32::Foundation::HANDLE,
    log_path: Option<&Path>,
    volparams_version: u16,
) -> Result<()> {
    eprintln!(
        "[VFS] mount_vault: vault={:?} drive={}:",
        vault_path.display(),
        drive_letter
    );
    init_global_cb_log(log_path);
    let log = log_path.and_then(|p| match VfsLog::open(p) {
        Ok(l) => {
            eprintln!("[VFS] logging to {:?}", p);
            Some(l)
        }
        Err(e) => {
            eprintln!("[VFS] failed to open log {:?}: {e}", p);
            None
        }
    });
    log_cb_line!(
        "INIT mount_vault drive={drive_letter}: vault={}",
        vault_path.display()
    );
    vlog!(
        log,
        "INIT mount_vault drive={drive_letter}: vault={}",
        vault_path.display()
    );

    // Open the vault.
    let mut vault =
        VaultContainer::open(vault_path, master_key).map_err(|e| FsError::Other(e.to_string()))?;

    // Diagnostic: log vault state on mount so the GUI log shows what we opened.
    let root_entries = vault.list_dir("/").unwrap_or_default();
    eprintln!(
        "[obsidianq-fs] vault opened: {} block(s), {} root entr(ies)",
        vault.total_blocks(),
        root_entries.len()
    );
    for e in &root_entries {
        eprintln!("[obsidianq-fs]   {:?}  size={}", e.name, e.size);
    }

    let usable = vault.block_usable_bytes();
    let total = (vault.total_blocks() * usable).max(4096);

    // Volume params: CasePreservedNames | UnicodeOnDisk — no ReadOnlyVolume.
    let mut params = FspFsctlVolumeParams::new(total, "ObsidianQV");
    params.Version = volparams_version;
    params.Flags &= !(1u32 << 9); // clear ReadOnlyVolume
    params.Flags &= !(1u32 << 3); // clear PersistentAcls
    params.FileInfoTimeout = 0; // disable metadata caching so Explorer always sees fresh data
    log_cb_line!(
        "INIT real params: ver={} sector={} spa={} max_comp={} flags=0x{:08X} fitime={}",
        params.Version,
        params.SectorSize,
        params.SectorsPerAllocationUnit,
        params.MaxComponentLength,
        params.Flags,
        params.FileInfoTimeout
    );

    let fs_box = Box::new(ObsqVaultFs {
        state: Arc::new(Mutex::new(VaultState {
            vault,
            handles: HashMap::new(),
            next_id: 1, // ≥ 1 so handle_id as PVOID is never null
        })),
        log,
    });

    let device_path = str_to_wchar_vec("WinFsp.Disk");
    let mount_point = str_to_wchar_vec(&format!("{drive_letter}:"));
    let mut fsp_ptr: *mut FspFileSystem = std::ptr::null_mut();

    let status = unsafe {
        FspFileSystemCreate(
            device_path.as_ptr(),
            &params,
            &VAULT_INTERFACE,
            &mut fsp_ptr,
        )
    };
    if status != STATUS_SUCCESS {
        if status == STATUS_NO_SUCH_DEVICE {
            return Err(FsError::WinFspDriverNotRunning);
        }
        return Err(FsError::WinFsp(status));
    }

    unsafe {
        FspFileSystemSetUserContext(fsp_ptr, Box::as_ref(&fs_box) as *const ObsqVaultFs as PVOID);
    }

    let status = unsafe { FspFileSystemSetMountPoint(fsp_ptr, mount_point.as_ptr()) };
    if status != STATUS_SUCCESS {
        unsafe {
            FspFileSystemDelete(fsp_ptr);
        }
        return Err(FsError::WinFsp(status));
    }
    if let Some(glog) = GLOBAL_CB_LOG.get() {
        if let Ok(f) = glog.file.lock() {
            unsafe {
                FspDebugLogSetHandle(f.as_raw_handle() as HANDLE);
            }
        }
    }
    unsafe {
        FspFileSystemSetDebugLogF(fsp_ptr, 0xFFFF_FFFF);
    }

    let status = unsafe { FspFileSystemStartDispatcher(fsp_ptr, 0) };
    if status != STATUS_SUCCESS {
        unsafe {
            FspFileSystemDelete(fsp_ptr);
        }
        return Err(FsError::WinFsp(status));
    }

    println!("Mounted vault: {drive_letter}: (read/write)");
    println!("Press Ctrl+C or run 'obsidianq vault unmount --drive {drive_letter}:' to dismount.");
    // Flush both streams so harnesses that redirect stdout/stderr can detect readiness
    // immediately without waiting for the process-exit flush.
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let _ = std::io::Write::flush(&mut std::io::stderr());

    // Block until Ctrl+C or unmount signal.
    unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(stop_event, 0xFFFFFFFF);
    }

    // Graceful shutdown: flush vault before stopping the dispatcher.
    {
        let mut st = fs_box.state.lock().unwrap();
        if let Err(e) = st.vault.flush() {
            eprintln!("[obsidianq-fs] vault flush on unmount error: {e}");
        }
    }

    unsafe {
        FspFileSystemStopDispatcher(fsp_ptr);
    }
    unsafe {
        FspFileSystemDelete(fsp_ptr);
    }
    println!("Unmounted vault {drive_letter}:");

    // Drop the fs_box — VaultContainer (and MasterKey) are zeroized here.
    drop(fs_box);
    Ok(())
}

// ===========================================================================
// Mock filesystem — diagnostic mode (obsidianq vault mount --mock)
//
// Mounts a static in-memory filesystem with one file so that `dir X:\` and
// Explorer can be tested without opening a real vault.  If this works but the
// real vault mount doesn't, the bug is in VaultContainer; if this also fails,
// the bug is in the WinFSP callback wiring or volume params.
// ===========================================================================

const MOCK_HELLO_CONTENT: &[u8] = b"Hello from ObsidianQ mock filesystem!\n";

struct MockHandle {
    path: String,
    is_dir: bool,
}

struct MockState {
    handles: HashMap<u64, MockHandle>,
    next_id: u64,
}

pub struct MockFs {
    state: Arc<Mutex<MockState>>,
    log: Option<Arc<VfsLog>>,
}

unsafe impl Send for MockFs {}
unsafe impl Sync for MockFs {}

fn mock_file_info(path: &str) -> Option<(FspFsctlFileInfo, bool)> {
    let now = now_windows_time();
    match path {
        "/" | "" => {
            let fi = FspFsctlFileInfo {
                FileAttributes: FILE_ATTRIBUTE_DIRECTORY,
                ReparseTag: 0,
                AllocationSize: 0,
                FileSize: 0,
                CreationTime: now,
                LastAccessTime: now,
                LastWriteTime: now,
                ChangeTime: now,
                IndexNumber: 1,
                HardLinks: 1,
                EaSize: 0,
            };
            Some((fi, true))
        }
        "/hello.txt" => {
            let sz = MOCK_HELLO_CONTENT.len() as u64;
            let fi = FspFsctlFileInfo {
                FileAttributes: FILE_ATTRIBUTE_NORMAL,
                ReparseTag: 0,
                AllocationSize: sz,
                FileSize: sz,
                CreationTime: now,
                LastAccessTime: now,
                LastWriteTime: now,
                ChangeTime: now,
                IndexNumber: 2,
                HardLinks: 1,
                EaSize: 0,
            };
            Some((fi, false))
        }
        _ => None,
    }
}

unsafe fn get_mock<'a>(fsp: *mut FspFileSystem) -> &'a MockFs {
    let ptr = unsafe { FspFileSystemGetUserContext(fsp) } as *const MockFs;
    unsafe { &*ptr }
}

unsafe extern "system" fn mock_cb_get_volume_info(
    fsp: *mut FspFileSystem,
    info: *mut FspFsctlVolumeInfo,
) -> NTSTATUS {
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.GetVolumeInfo ctx=0x{ctx:016X} ctx_null={} info_null={}",
        ctx == 0,
        info.is_null()
    );
    if fsp.is_null() || info.is_null() {
        log_cb_line!(
            "EXIT  MOCK.GetVolumeInfo status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.GetVolumeInfo status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    eprintln!("[MOCK] GetVolumeInfo");
    vlog!(log, "CALL GetVolumeInfo");
    let out = unsafe { &mut *info };
    out.TotalSize = 65536;
    out.FreeSize = 65536 - MOCK_HELLO_CONTENT.len() as u64;
    out.VolumeLabelLength = ("MockVault".encode_utf16().count() * 2) as UINT16;
    str_to_wchar_fixed("MockVault", &mut out.VolumeLabel);
    eprintln!("[MOCK] GetVolumeInfo -> SUCCESS");
    log_cb_line!("EXIT  MOCK.GetVolumeInfo status={:#010x}", STATUS_SUCCESS);
    vlog!(log, "RETN GetVolumeInfo -> {:#010x}", STATUS_SUCCESS);
    STATUS_SUCCESS
}

unsafe extern "system" fn mock_cb_get_security_by_name(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    p_file_attrs: *mut UINT32,
    _sec_desc: PVOID,
    sec_size: PSIZE_T,
) -> NTSTATUS {
    let path = wpath_to_vault(file_name);
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.GetSecurityByName ctx=0x{ctx:016X} ctx_null={} path={:?}",
        ctx == 0,
        path
    );
    if fsp.is_null() || file_name.is_null() {
        log_cb_line!(
            "EXIT  MOCK.GetSecurityByName path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.GetSecurityByName path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    eprintln!("[MOCK] GetSecurityByName {:?}", path);
    vlog!(log, "CALL GetSecurityByName path={:?}", path);
    if !sec_size.is_null() {
        unsafe {
            *sec_size = 0;
        }
    }
    let r = match mock_file_info(&path) {
        Some((fi, _)) => {
            if !p_file_attrs.is_null() {
                unsafe {
                    *p_file_attrs = fi.FileAttributes;
                }
            }
            eprintln!(
                "[MOCK] GetSecurityByName {:?} -> SUCCESS attrs={:#x}",
                path, fi.FileAttributes
            );
            STATUS_SUCCESS
        }
        None => {
            eprintln!("[MOCK] GetSecurityByName {:?} -> NOT_FOUND", path);
            STATUS_OBJECT_NAME_NOT_FOUND
        }
    };
    log_cb_line!(
        "EXIT  MOCK.GetSecurityByName path={:?} status={r:#010x}",
        path
    );
    vlog!(log, "RETN GetSecurityByName path={:?} -> {r:#010x}", path);
    r
}

unsafe extern "system" fn mock_cb_open(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    _opts: UINT32,
    _granted: UINT32,
    p_fc: *mut PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let path = wpath_to_vault(file_name);
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.Open ctx=0x{ctx:016X} ctx_null={} path={:?}",
        ctx == 0,
        path
    );
    if fsp.is_null() || file_name.is_null() || p_fc.is_null() || p_info.is_null() {
        log_cb_line!(
            "EXIT  MOCK.Open path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.Open path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    eprintln!("[MOCK] Open {:?}", path);
    vlog!(log, "CALL Open path={:?}", path);
    let r = match mock_file_info(&path) {
        Some((fi, is_dir)) => {
            let fs = unsafe { get_mock(fsp) };
            let mut st = fs.state.lock().unwrap();
            let id = st.next_id;
            st.next_id += 1;
            st.handles.insert(
                id,
                MockHandle {
                    path: path.clone(),
                    is_dir,
                },
            );
            unsafe {
                *p_fc = id as usize as PVOID;
                *p_info = fi;
            }
            eprintln!(
                "[MOCK] Open {:?} -> SUCCESS handle={} dir={}",
                path, id, is_dir
            );
            vlog!(
                log,
                "     Open path={:?} -> handle={id} is_dir={is_dir}",
                path
            );
            STATUS_SUCCESS
        }
        None => {
            eprintln!("[MOCK] Open {:?} -> NOT_FOUND", path);
            STATUS_OBJECT_NAME_NOT_FOUND
        }
    };
    log_cb_line!("EXIT  MOCK.Open path={:?} status={r:#010x}", path);
    vlog!(log, "RETN Open path={:?} -> {r:#010x}", path);
    r
}

unsafe extern "system" fn mock_cb_create(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    _create_opts: UINT32,
    _granted: UINT32,
    _file_attrs: UINT32,
    _sec_desc: PVOID,
    _alloc_size: UINT64,
    p_fc: *mut PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let path = wpath_to_vault(file_name);
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.Create ctx=0x{ctx:016X} ctx_null={} path={:?}",
        ctx == 0,
        path
    );
    if fsp.is_null() || file_name.is_null() || p_fc.is_null() || p_info.is_null() {
        log_cb_line!(
            "EXIT  MOCK.Create path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.Create path={:?} status={:#010x}",
            path,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    vlog!(log, "CALL Create path={:?}", path);
    let r = match mock_file_info(&path) {
        Some((fi, is_dir)) => {
            let fs = unsafe { get_mock(fsp) };
            let mut st = fs.state.lock().unwrap();
            let id = st.next_id;
            st.next_id += 1;
            st.handles.insert(
                id,
                MockHandle {
                    path: path.clone(),
                    is_dir,
                },
            );
            unsafe {
                *p_fc = id as usize as PVOID;
                *p_info = fi;
            }
            STATUS_SUCCESS
        }
        None => STATUS_OBJECT_NAME_NOT_FOUND,
    };
    log_cb_line!("EXIT  MOCK.Create path={:?} status={r:#010x}", path);
    vlog!(log, "RETN Create path={:?} -> {r:#010x}", path);
    r
}

unsafe extern "system" fn mock_cb_create_legacy(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    create_opts: UINT32,
    granted: UINT32,
    file_attrs: UINT32,
    sec_desc: PVOID,
    alloc_size: UINT64,
    p_fc: *mut PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let path = wpath_to_vault(file_name);
    log_cb_line!("ENTER MOCK.CreateLegacy path={:?}", path);
    let r = mock_cb_create(
        fsp,
        file_name,
        create_opts,
        granted,
        file_attrs,
        sec_desc,
        alloc_size,
        p_fc,
        p_info,
    );
    log_cb_line!("EXIT  MOCK.CreateLegacy path={:?} status={r:#010x}", path);
    r
}

unsafe extern "system" fn mock_cb_create_ex(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    create_opts: UINT32,
    granted: UINT32,
    file_attrs: UINT32,
    sec_desc: PVOID,
    alloc_size: UINT64,
    _extra: PVOID,
    _extra_len: ULONG,
    _extra_is_rp: BOOLEAN,
    p_fc: *mut PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let path = wpath_to_vault(file_name);
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.CreateEx ctx=0x{ctx:016X} ctx_null={} path={:?}",
        ctx == 0,
        path
    );
    let r = mock_cb_create(
        fsp,
        file_name,
        create_opts,
        granted,
        file_attrs,
        sec_desc,
        alloc_size,
        p_fc,
        p_info,
    );
    log_cb_line!("EXIT  MOCK.CreateEx path={:?} status={r:#010x}", path);
    r
}

unsafe extern "system" fn mock_cb_cleanup(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _filename: PWSTR,
    flags: UINT32,
) {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.Cleanup ctx=0x{ctx:016X} ctx_null={} handle={id} flags={flags:#x}",
        ctx == 0
    );
    eprintln!("[MOCK] Cleanup handle={id} flags={flags:#x}");
    if fsp.is_null() || ctx == 0 {
        log_cb_line!("EXIT  MOCK.Cleanup handle={id}");
        return;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    vlog!(log, "CALL Cleanup handle={id} flags={flags:#x}");
    log_cb_line!("EXIT  MOCK.Cleanup handle={id}");
}

unsafe extern "system" fn mock_cb_close(fsp: *mut FspFileSystem, fc: PVOID) {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.Close ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() || ctx == 0 {
        log_cb_line!("EXIT  MOCK.Close handle={id}");
        return;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    eprintln!("[MOCK] Close handle={id}");
    vlog!(log, "CALL Close handle={id}");
    let fs = unsafe { get_mock(fsp) };
    let mut st = fs.state.lock().unwrap();
    st.handles.remove(&id);
    vlog!(log, "RETN Close handle={id}");
    log_cb_line!("EXIT  MOCK.Close handle={id}");
}

unsafe extern "system" fn mock_cb_read(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    buffer: PVOID,
    offset: UINT64,
    length: ULONG,
    p_bt: PULONG,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.Read ctx=0x{ctx:016X} ctx_null={} handle={id} offset={offset} len={length}",
        ctx == 0
    );
    if fsp.is_null() || p_bt.is_null() {
        log_cb_line!(
            "EXIT  MOCK.Read handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.Read handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    eprintln!("[MOCK] Read handle={id} offset={offset} len={length}");
    vlog!(log, "CALL Read handle={id} offset={offset} len={length}");
    unsafe {
        *p_bt = 0;
    }
    if buffer.is_null() || length == 0 {
        log_cb_line!(
            "EXIT  MOCK.Read handle={id} status={:#010x}",
            STATUS_SUCCESS
        );
        return STATUS_SUCCESS;
    }
    let id = fc as u64;
    let fs = unsafe { get_mock(fsp) };
    let st = fs.state.lock().unwrap();
    let r = match st.handles.get(&id) {
        Some(h) if !h.is_dir && h.path == "/hello.txt" => {
            let src = MOCK_HELLO_CONTENT;
            let off = offset as usize;
            if off >= src.len() {
                log_cb_line!(
                    "EXIT  MOCK.Read handle={id} status={:#010x}",
                    STATUS_END_OF_FILE
                );
                vlog!(log, "RETN Read handle={id} -> END_OF_FILE");
                return STATUS_END_OF_FILE;
            }
            let avail = src.len() - off;
            let n = (length as usize).min(avail);
            unsafe {
                std::ptr::copy_nonoverlapping(src.as_ptr().add(off), buffer as *mut u8, n);
                *p_bt = n as ULONG;
            }
            STATUS_SUCCESS
        }
        _ => STATUS_ACCESS_DENIED,
    };
    log_cb_line!("EXIT  MOCK.Read handle={id} status={r:#010x}");
    vlog!(log, "RETN Read handle={id} -> {r:#010x}");
    r
}

unsafe extern "system" fn mock_cb_get_file_info(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.GetFileInfo ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() || p_info.is_null() {
        log_cb_line!(
            "EXIT  MOCK.GetFileInfo handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.GetFileInfo handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    eprintln!("[MOCK] GetFileInfo handle={id}");
    vlog!(log, "CALL GetFileInfo handle={id}");
    let fs = unsafe { get_mock(fsp) };
    let st = fs.state.lock().unwrap();
    let r = match st.handles.get(&id) {
        Some(h) => match mock_file_info(&h.path) {
            Some((fi, _)) => {
                unsafe {
                    *p_info = fi;
                }
                STATUS_SUCCESS
            }
            None => STATUS_OBJECT_NAME_NOT_FOUND,
        },
        None => STATUS_OBJECT_NAME_NOT_FOUND,
    };
    eprintln!("[MOCK] GetFileInfo handle={id} -> {r:#010x}");
    log_cb_line!("EXIT  MOCK.GetFileInfo handle={id} status={r:#010x}");
    vlog!(log, "RETN GetFileInfo handle={id} -> {r:#010x}");
    r
}

unsafe extern "system" fn mock_cb_get_security(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _sec: PVOID,
    sec_size: PSIZE_T,
) -> NTSTATUS {
    let id = fc as u64;
    eprintln!("[MOCK] GetSecurity handle={id}");
    if !sec_size.is_null() {
        unsafe {
            *sec_size = 0;
        }
    }
    if !fsp.is_null() {
        let log = &unsafe { get_mock(fsp) }.log;
        vlog!(log, "CALL GetSecurity handle={id}");
        vlog!(
            log,
            "RETN GetSecurity handle={id} -> {:#010x}",
            STATUS_SUCCESS
        );
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn mock_cb_flush(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.Flush ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() {
        log_cb_line!(
            "EXIT  MOCK.Flush handle={id} status={:#010x}",
            STATUS_SUCCESS
        );
        return STATUS_SUCCESS;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.Flush handle={id} status={:#010x}",
            STATUS_SUCCESS
        );
        return STATUS_SUCCESS;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    eprintln!("[MOCK] Flush handle={id}");
    vlog!(log, "CALL Flush handle={id}");
    // Fill p_info if a handle was given.
    if id != 0 && !p_info.is_null() {
        let fs = unsafe { get_mock(fsp) };
        let st = fs.state.lock().unwrap();
        if let Some(h) = st.handles.get(&id) {
            if let Some((fi, _)) = mock_file_info(&h.path) {
                unsafe {
                    *p_info = fi;
                }
            }
        }
    }
    eprintln!("[MOCK] Flush handle={id} -> SUCCESS");
    log_cb_line!(
        "EXIT  MOCK.Flush handle={id} status={:#010x}",
        STATUS_SUCCESS
    );
    vlog!(log, "RETN Flush handle={id} -> {:#010x}", STATUS_SUCCESS);
    STATUS_SUCCESS
}

unsafe extern "system" fn mock_cb_set_basic_info(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _fa: UINT32,
    _ctime: UINT64,
    _atime: UINT64,
    _mtime: UINT64,
    _chgtime: UINT64,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.SetBasicInfo ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() || p_info.is_null() {
        log_cb_line!(
            "EXIT  MOCK.SetBasicInfo handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.SetBasicInfo handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    eprintln!("[MOCK] SetBasicInfo handle={id}");
    vlog!(log, "CALL SetBasicInfo handle={id}");
    // Return current (static) file info — timestamps are immutable in mock.
    let fs = unsafe { get_mock(fsp) };
    let st = fs.state.lock().unwrap();
    let r = if let Some(h) = st.handles.get(&id) {
        if let Some((fi, _)) = mock_file_info(&h.path) {
            unsafe {
                *p_info = fi;
            }
            eprintln!("[MOCK] SetBasicInfo handle={id} -> SUCCESS");
            STATUS_SUCCESS
        } else {
            eprintln!("[MOCK] SetBasicInfo handle={id} -> PATH_NOT_FOUND");
            STATUS_OBJECT_NAME_NOT_FOUND
        }
    } else {
        eprintln!("[MOCK] SetBasicInfo handle={id} -> HANDLE_NOT_FOUND");
        STATUS_OBJECT_NAME_NOT_FOUND
    };
    log_cb_line!("EXIT  MOCK.SetBasicInfo handle={id} status={r:#010x}");
    vlog!(log, "RETN SetBasicInfo handle={id} -> {r:#010x}");
    r
}

unsafe extern "system" fn mock_cb_can_delete(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _filename: PWSTR,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.CanDelete ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() {
        log_cb_line!(
            "EXIT  MOCK.CanDelete handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.CanDelete handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let log = &unsafe { get_mock(fsp) }.log;
    eprintln!("[MOCK] CanDelete handle={id}");
    vlog!(log, "CALL CanDelete handle={id}");
    // Mock is read-only; deny all deletes.
    log_cb_line!(
        "EXIT  MOCK.CanDelete handle={id} status={:#010x}",
        STATUS_ACCESS_DENIED
    );
    vlog!(log, "RETN CanDelete handle={id} -> ACCESS_DENIED");
    STATUS_ACCESS_DENIED
}

unsafe extern "system" fn mock_cb_read_directory(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _pat: PWSTR,
    marker: PWSTR,
    buffer: PVOID,
    length: ULONG,
    p_bt: PULONG,
) -> NTSTATUS {
    let id = fc as u64;
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.ReadDirectory ctx=0x{ctx:016X} ctx_null={} handle={id}",
        ctx == 0
    );
    if fsp.is_null() || p_bt.is_null() {
        log_cb_line!(
            "EXIT  MOCK.ReadDirectory handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.ReadDirectory handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        *p_bt = 0;
    }
    if buffer.is_null() && length != 0 {
        log_cb_line!(
            "EXIT  MOCK.ReadDirectory handle={id} status={:#010x}",
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }

    let log = &unsafe { get_mock(fsp) }.log;
    let fs = unsafe { get_mock(fsp) };
    let st = fs.state.lock().unwrap();
    let h = match st.handles.get(&id) {
        Some(h) => h,
        None => {
            eprintln!("[MOCK] ReadDirectory: handle {id} not found");
            log_cb_line!(
                "EXIT  MOCK.ReadDirectory handle={id} status={:#010x}",
                STATUS_OBJECT_NAME_NOT_FOUND
            );
            vlog!(log, "RETN ReadDirectory handle={id} -> NOT_IN_MAP");
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    };
    if !h.is_dir {
        log_cb_line!(
            "EXIT  MOCK.ReadDirectory handle={id} status={:#010x}",
            STATUS_NOT_A_DIRECTORY
        );
        return STATUS_NOT_A_DIRECTORY;
    }

    let marker_str = if marker.is_null() {
        String::new()
    } else {
        unsafe { wchar_to_string(marker) }
    };
    let marker_lower = marker_str.to_ascii_lowercase();
    let is_past = |name: &str| !marker_str.is_empty() && name.to_ascii_lowercase() <= marker_lower;

    eprintln!("[MOCK] ReadDirectory {:?} marker={:?}", h.path, marker_str);
    vlog!(
        log,
        "CALL ReadDirectory path={:?} handle={id} marker={:?}",
        h.path,
        marker_str
    );

    macro_rules! try_add {
        ($di:expr) => {{
            let ok = unsafe { FspFileSystemAddDirInfo($di, buffer, length, p_bt) };
            if ok == 0 {
                log_cb_line!(
                    "EXIT  MOCK.ReadDirectory handle={id} status={:#010x}",
                    STATUS_SUCCESS
                );
                return STATUS_SUCCESS;
            }
        }};
    }

    let now = now_windows_time();
    let dir_fi = FspFsctlFileInfo {
        FileAttributes: FILE_ATTRIBUTE_DIRECTORY,
        ReparseTag: 0,
        AllocationSize: 0,
        FileSize: 0,
        CreationTime: now,
        LastAccessTime: now,
        LastWriteTime: now,
        ChangeTime: now,
        IndexNumber: 1,
        HardLinks: 1,
        EaSize: 0,
    };

    if !is_past(".") {
        let mut di = FspFsctlDirInfo::new(dir_fi, ".");
        try_add!(&mut di);
    }
    if !is_past("..") {
        let mut di = FspFsctlDirInfo::new(dir_fi, "..");
        try_add!(&mut di);
    }

    // The only file: hello.txt
    if !is_past("hello.txt") {
        let sz = MOCK_HELLO_CONTENT.len() as u64;
        let file_fi = FspFsctlFileInfo {
            FileAttributes: FILE_ATTRIBUTE_NORMAL,
            ReparseTag: 0,
            AllocationSize: sz,
            FileSize: sz,
            CreationTime: now,
            LastAccessTime: now,
            LastWriteTime: now,
            ChangeTime: now,
            IndexNumber: 2,
            HardLinks: 1,
            EaSize: 0,
        };
        let mut di = FspFsctlDirInfo::new(file_fi, "hello.txt");
        try_add!(&mut di);
    }

    eprintln!("[MOCK] ReadDirectory -> done");
    log_cb_line!(
        "EXIT  MOCK.ReadDirectory handle={id} status={:#010x}",
        STATUS_SUCCESS
    );
    vlog!(
        log,
        "RETN ReadDirectory handle={id} marker={:?} -> {:#010x}",
        marker_str,
        STATUS_SUCCESS
    );
    unsafe {
        FspFileSystemAddDirInfo(std::ptr::null_mut(), buffer, length, p_bt);
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn mock_cb_get_dir_info_by_name(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    file_name: PWSTR,
    dir_info: *mut FspFsctlDirInfo,
) -> NTSTATUS {
    let id = fc as u64;
    let name = if file_name.is_null() {
        String::new()
    } else {
        unsafe { wchar_to_string(file_name) }
    };
    let ctx = user_context_ptr(fsp);
    log_cb_line!(
        "ENTER MOCK.GetDirInfoByName ctx=0x{ctx:016X} ctx_null={} handle={id} name={:?}",
        ctx == 0,
        name
    );
    if fsp.is_null() || file_name.is_null() || dir_info.is_null() {
        log_cb_line!(
            "EXIT  MOCK.GetDirInfoByName handle={id} name={:?} status={:#010x}",
            name,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    if ctx == 0 {
        log_cb_line!(
            "EXIT  MOCK.GetDirInfoByName handle={id} name={:?} status={:#010x}",
            name,
            STATUS_INVALID_PARAMETER
        );
        return STATUS_INVALID_PARAMETER;
    }
    let fs = unsafe { get_mock(fsp) };
    let st = fs.state.lock().unwrap();
    let parent = match st.handles.get(&id) {
        Some(h) if h.is_dir => h.path.clone(),
        Some(_) => return STATUS_NOT_A_DIRECTORY,
        None => return STATUS_OBJECT_NAME_NOT_FOUND,
    };
    let full = if parent == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", parent, name)
    };
    let r = match mock_file_info(&full) {
        Some((fi, _)) => {
            unsafe {
                *dir_info = FspFsctlDirInfo::new(fi, &name);
            }
            STATUS_SUCCESS
        }
        None => STATUS_OBJECT_NAME_NOT_FOUND,
    };
    log_cb_line!(
        "EXIT  MOCK.GetDirInfoByName handle={id} name={:?} status={r:#010x}",
        name
    );
    r
}

unsafe extern "system" fn mock_cb_dispatcher_stopped(_fsp: *mut FspFileSystem, normally: BOOLEAN) {
    if normally != 0 {
        eprintln!("[MOCK] dispatcher stopped normally.");
        return;
    }
    eprintln!("[MOCK] dispatcher stopped ABNORMALLY — signaling stop.");
    use std::sync::atomic::Ordering;
    let h =
        crate::STOP_EVENT_HANDLE.load(Ordering::Relaxed) as windows_sys::Win32::Foundation::HANDLE;
    if !h.is_null() {
        unsafe {
            windows_sys::Win32::System::Threading::SetEvent(h);
        }
    }
}

fn build_mock_interface() -> FspFileSystemInterface {
    FspFileSystemInterface {
        get_volume_info: Some(mock_cb_get_volume_info),
        set_volume_label: None,
        get_security_by_name: Some(mock_cb_get_security_by_name),
        create: Some(mock_cb_create_legacy),
        open: Some(mock_cb_open),
        overwrite: None,
        cleanup: Some(mock_cb_cleanup),
        close: Some(mock_cb_close),
        read: Some(mock_cb_read),
        write: None,
        flush: Some(mock_cb_flush),
        get_file_info: Some(mock_cb_get_file_info),
        set_basic_info: Some(mock_cb_set_basic_info),
        set_file_size: None,
        can_delete: Some(mock_cb_can_delete),
        rename: None,
        get_security: Some(mock_cb_get_security),
        set_security: None,
        read_directory: Some(mock_cb_read_directory),
        resolve_reparse_points: None,
        get_reparse_point: None,
        set_reparse_point: None,
        delete_reparse_point: None,
        get_stream_info: None,
        get_dir_info_by_name: Some(mock_cb_get_dir_info_by_name),
        control: None,
        set_delete: None,
        create_ex: Some(mock_cb_create_ex),
        overwrite_ex: None,
        get_ea: None,
        set_ea: None,
        obsolete0: None,
        dispatcher_stopped: Some(mock_cb_dispatcher_stopped),
        _rest: [0usize; 31],
    }
}

struct MockMountState {
    fs_box: Box<MockFs>,
    iface: Box<FspFileSystemInterface>,
    params: Box<FspFsctlVolumeParams>,
}

/// Mount a read-only mock filesystem at `drive_letter:` for diagnostic testing.
///
/// The volume contains a single file `hello.txt` with fixed content.
/// Use `obsidianq vault mount --mock --drive X:` to test whether the WinFSP
/// callback wiring works independently of vault I/O.
pub fn mount_vault_mock(
    drive_letter: char,
    stop_event: windows_sys::Win32::Foundation::HANDLE,
    log_path: Option<&Path>,
    volparams_version: u16,
) -> Result<()> {
    eprintln!("[MOCK] mount_vault_mock: drive={}:", drive_letter);
    init_global_cb_log(log_path);
    let log = log_path.and_then(|p| match VfsLog::open(p) {
        Ok(l) => {
            eprintln!("[MOCK] logging to {:?}", p);
            Some(l)
        }
        Err(e) => {
            eprintln!("[MOCK] failed to open log {:?}: {e}", p);
            None
        }
    });
    log_cb_line!("INIT mount_vault_mock drive={drive_letter}:");
    vlog!(log, "INIT mount_vault_mock drive={drive_letter}:");
    let mut mount_state = MockMountState {
        fs_box: Box::new(MockFs {
            state: Arc::new(Mutex::new(MockState {
                handles: HashMap::new(),
                next_id: 1,
            })),
            log,
        }),
        iface: Box::new(build_mock_interface()),
        // Zero-init + fill minimal conservative fields.
        params: Box::new(unsafe { std::mem::zeroed::<FspFsctlVolumeParams>() }),
    };
    mount_state.params.Version = volparams_version;
    mount_state.params.SectorSize = 512;
    mount_state.params.SectorsPerAllocationUnit = 1;
    mount_state.params.MaxComponentLength = 255;
    mount_state.params.FileInfoTimeout = 0;
    mount_state.params.Flags = (1u32 << 1) | (1u32 << 2) | (1u32 << 9); // CasePreserved + Unicode + ReadOnly
    str_to_wchar_fixed("ObsidianQ", &mut mount_state.params.FileSystemName);
    log_cb_line!(
        "INIT mock params: ptr=0x{:016X} ver={} sector={} spa={} max_comp={} flags=0x{:08X} fitime={} fsname={:?}",
        (&*mount_state.params as *const FspFsctlVolumeParams) as usize,
        mount_state.params.Version,
        mount_state.params.SectorSize,
        mount_state.params.SectorsPerAllocationUnit,
        mount_state.params.MaxComponentLength,
        mount_state.params.Flags,
        mount_state.params.FileInfoTimeout,
        "ObsidianQ"
    );
    log_cb_line!(
        "INIT mock pointers: iface=0x{:016X} fs=0x{:016X}",
        (&*mount_state.iface as *const FspFileSystemInterface) as usize,
        (&*mount_state.fs_box as *const MockFs) as usize
    );
    let base = (&*mount_state.iface as *const FspFileSystemInterface) as usize;
    let off_create = (&mount_state.iface.create as *const _ as usize) - base;
    let off_create_ex = (&mount_state.iface.create_ex as *const _ as usize) - base;
    log_cb_line!(
        "INIT mock interface offsets: create={} create_ex={}",
        off_create,
        off_create_ex
    );

    let device_path = str_to_wchar_vec("WinFsp.Disk");
    let mount_point = str_to_wchar_vec(&format!("{drive_letter}:"));
    let mut fsp_ptr: *mut FspFileSystem = std::ptr::null_mut();

    let status = unsafe {
        FspFileSystemCreate(
            device_path.as_ptr(),
            &*mount_state.params,
            &*mount_state.iface,
            &mut fsp_ptr,
        )
    };
    log_cb_line!(
        "CALL FspFileSystemCreate iface=0x{:016X} params=0x{:016X} -> status={status:#010x} fsp=0x{:016X}",
        (&*mount_state.iface as *const FspFileSystemInterface) as usize,
        (&*mount_state.params as *const FspFsctlVolumeParams) as usize,
        fsp_ptr as usize
    );
    if status != STATUS_SUCCESS {
        if status == STATUS_NO_SUCH_DEVICE {
            return Err(FsError::WinFspDriverNotRunning);
        }
        return Err(FsError::WinFsp(status));
    }

    unsafe { FspFileSystemSetUserContext(fsp_ptr, Box::as_ref(&mount_state.fs_box) as *const MockFs as PVOID) };
    log_cb_line!(
        "CALL FspFileSystemSetUserContext fsp=0x{:016X} ctx=0x{:016X}",
        fsp_ptr as usize,
        (Box::as_ref(&mount_state.fs_box) as *const MockFs) as usize
    );

    let status = unsafe { FspFileSystemSetMountPoint(fsp_ptr, mount_point.as_ptr()) };
    log_cb_line!(
        "CALL FspFileSystemSetMountPoint fsp=0x{:016X} mp={} -> status={status:#010x}",
        fsp_ptr as usize,
        format!("{drive_letter}:")
    );
    if status != STATUS_SUCCESS {
        unsafe {
            FspFileSystemDelete(fsp_ptr);
        }
        return Err(FsError::WinFsp(status));
    }
    if let Some(glog) = GLOBAL_CB_LOG.get() {
        if let Ok(f) = glog.file.lock() {
            unsafe {
                FspDebugLogSetHandle(f.as_raw_handle() as HANDLE);
            }
        }
    }
    unsafe {
        FspFileSystemSetDebugLogF(fsp_ptr, 0xFFFF_FFFF);
    }

    let status = unsafe { FspFileSystemStartDispatcher(fsp_ptr, 0) };
    log_cb_line!(
        "CALL FspFileSystemStartDispatcher fsp=0x{:016X} -> status={status:#010x}",
        fsp_ptr as usize
    );
    if status != STATUS_SUCCESS {
        unsafe {
            FspFileSystemDelete(fsp_ptr);
        }
        return Err(FsError::WinFsp(status));
    }

    println!("Mounted mock vault: {drive_letter}: (read-only, diagnostic)");
    println!("Contains: /hello.txt ({} bytes)", MOCK_HELLO_CONTENT.len());
    println!("Run 'obsidianq vault unmount --drive {drive_letter}:' to dismount.");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let _ = std::io::Write::flush(&mut std::io::stderr());

    unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(stop_event, 0xFFFFFFFF);
    }
    log_cb_line!(
        "UNMOUNT mock pointers: iface=0x{:016X} params=0x{:016X} fs=0x{:016X}",
        (&*mount_state.iface as *const FspFileSystemInterface) as usize,
        (&*mount_state.params as *const FspFsctlVolumeParams) as usize,
        (&*mount_state.fs_box as *const MockFs) as usize
    );

    unsafe {
        FspFileSystemStopDispatcher(fsp_ptr);
    }
    unsafe {
        FspFileSystemDelete(fsp_ptr);
    }
    println!("Unmounted mock vault {drive_letter}:");
    drop(mount_state);
    Ok(())
}
