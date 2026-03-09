//! WinFSP virtual filesystem implementation for ObsidianQ containers.
//!
//! Exposes a single decrypted file under the virtual drive root.
//! All write operations return STATUS_MEDIA_WRITE_PROTECTED.
//!
//! SAFETY NOTES:
//! - `ObsqFs` is pinned in a `Box` before its raw pointer is given to WinFSP.
//!   The Box is kept alive for the lifetime of the mount.
//! - `FileContext` is encoded as an integer constant (FC_ROOT=1, FC_FILE=2)
//!   cast to PVOID — no heap allocation, no free, no corruption possible.
//! - All accesses to `ObsqFs` fields from callbacks are via shared references
//!   (no mutation after construction), making the impl Send + Sync safe.

#![allow(non_snake_case)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use obsidianq_core::{crypto::kdf::MasterKey, ContainerManifest};

use crate::chunk_io::read_virtual;
use crate::error::{FsError, Result};
use crate::ffi::*;

// ---------------------------------------------------------------------------
// SetUnhandledExceptionFilter -- raw declaration (kernel32 is already linked)
// ---------------------------------------------------------------------------
//
// We declare this ourselves to avoid pulling in the Win32_System_Diagnostics_Debug
// windows-sys feature (which drags in the full CONTEXT struct definition).
// The function pointer parameter is typed as *mut u8 (opaque pointer); we read
// fields via raw offset arithmetic in obsq_crash_filter below.

type ExFilterFn = unsafe extern "system" fn(*mut u8) -> i32;

extern "system" {
    fn SetUnhandledExceptionFilter(filter: Option<ExFilterFn>) -> Option<ExFilterFn>;
}

// ---------------------------------------------------------------------------
// File context passed through WinFSP's PVOID FileContext
// ---------------------------------------------------------------------------

// FileContext is encoded as a small integer PVOID — no heap allocation.
// This completely avoids double-free and heap corruption risks.
//   FC_ROOT = 1  (root directory)
//   FC_FILE = 2  (the single decrypted file)
const FC_ROOT: usize = 1;
const FC_FILE: usize = 2;

// ---------------------------------------------------------------------------
// The main filesystem state (one instance per mount)
// ---------------------------------------------------------------------------

pub struct ObsqFs {
    container_path: PathBuf,
    master_key: Arc<MasterKey>, // Arc so the key outlives any WinFSP threads
    manifest: Arc<ContainerManifest>,
    filename: String,                 // virtual filename (basename without .obsq)
    file_info_file: FspFsctlFileInfo, // pre-built FileInfo for the single file
    file_info_dir: FspFsctlFileInfo,  // pre-built FileInfo for the root dir
}

impl ObsqFs {
    pub fn new(container_path: &Path, master_key: MasterKey, manifest: ContainerManifest) -> Self {
        let filename = container_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decrypted")
            .to_owned();

        let now = now_windows_time();
        let fsize = manifest.total_plaintext_len;
        let chunk = manifest.header.chunk_size as u64;
        let alloc = ((fsize + chunk - 1) / chunk) * chunk;

        let file_info_file = FspFsctlFileInfo {
            FileAttributes: FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL,
            ReparseTag: 0,
            AllocationSize: alloc,
            FileSize: fsize,
            CreationTime: now,
            LastAccessTime: now,
            LastWriteTime: now,
            ChangeTime: now,
            IndexNumber: 2, // 1 = root, 2 = the file
            HardLinks: 1,
            EaSize: 0,
        };
        let file_info_dir = FspFsctlFileInfo {
            FileAttributes: FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY,
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

        ObsqFs {
            container_path: container_path.to_owned(),
            master_key: Arc::new(master_key),
            manifest: Arc::new(manifest),
            filename,
            file_info_file,
            file_info_dir,
        }
    }

    /// Path matching. Returns:
    ///   Some(true)  = root directory ("\" or empty)
    ///   Some(false) = the single decrypted file
    ///   None        = not found
    fn classify_path(&self, raw_path: PWSTR) -> Option<bool> {
        let path = unsafe { wchar_to_string(raw_path) };
        let path = path.replace('\\', "/");
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            Some(true)
        } else if trimmed.eq_ignore_ascii_case(&self.filename) {
            Some(false)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// WinFSP callback trampolines
//
// All write/create/delete paths return STATUS_MEDIA_WRITE_PROTECTED.
// ---------------------------------------------------------------------------

/// Extract the `ObsqFs` reference from `FspFileSystemGetUserContext`.
///
/// # Safety
/// The pointer was placed by `mount_container` before the dispatcher started.
unsafe fn get_fs<'a>(fsp: *mut FspFileSystem) -> &'a ObsqFs {
    let ptr = unsafe { FspFileSystemGetUserContext(fsp) } as *const ObsqFs;
    unsafe { &*ptr }
}

unsafe extern "system" fn cb_get_volume_info(
    fsp: *mut FspFileSystem,
    info: *mut FspFsctlVolumeInfo,
) -> NTSTATUS {
    if fsp.is_null() || info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        let out = unsafe { &mut *info };
        // TotalSize must be the volume capacity, NOT the file size.
        // Use AllocationSize (chunk-rounded file size) so it is always
        // a whole number of sectors (>= SectorSize = 4096).
        out.TotalSize = fs.file_info_file.AllocationSize;
        out.FreeSize = 0;
        out.VolumeLabelLength = ("ObsidianQ".encode_utf16().count() * 2) as UINT16;
        str_to_wchar_fixed("ObsidianQ", &mut out.VolumeLabel);
        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in cb_get_volume_info");
        STATUS_ACCESS_DENIED
    })
}

unsafe extern "system" fn cb_get_security_by_name(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    p_file_attrs: *mut UINT32,
    _security_desc: PVOID,
    security_size: PSIZE_T,
) -> NTSTATUS {
    if fsp.is_null() || file_name.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        if !security_size.is_null() {
            unsafe {
                *security_size = 0;
            }
        }
        match fs.classify_path(file_name) {
            Some(true) => {
                // Root directory
                if !p_file_attrs.is_null() {
                    unsafe {
                        *p_file_attrs = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY;
                    }
                }
                STATUS_SUCCESS
            }
            Some(false) => {
                // The single file
                if !p_file_attrs.is_null() {
                    unsafe {
                        *p_file_attrs = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL;
                    }
                }
                STATUS_SUCCESS
            }
            None => STATUS_OBJECT_NAME_NOT_FOUND,
        }
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in cb_get_security_by_name");
        STATUS_ACCESS_DENIED
    })
}

unsafe extern "system" fn cb_open(
    fsp: *mut FspFileSystem,
    file_name: PWSTR,
    _create_opts: UINT32,
    _granted: UINT32,
    p_fc: *mut PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    if fsp.is_null() || file_name.is_null() || p_fc.is_null() || p_info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };
        match fs.classify_path(file_name) {
            Some(true) => {
                // Root directory
                unsafe {
                    *p_fc = FC_ROOT as PVOID;
                }
                unsafe {
                    *p_info = fs.file_info_dir;
                }
                STATUS_SUCCESS
            }
            Some(false) => {
                // The single file
                unsafe {
                    *p_fc = FC_FILE as PVOID;
                }
                unsafe {
                    *p_info = fs.file_info_file;
                }
                STATUS_SUCCESS
            }
            None => STATUS_OBJECT_NAME_NOT_FOUND,
        }
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in cb_open");
        STATUS_ACCESS_DENIED
    })
}

unsafe extern "system" fn cb_close(_fsp: *mut FspFileSystem, _fc: PVOID) {
    // FileContext is an integer constant, not a heap allocation — nothing to free.
}

unsafe extern "system" fn cb_cleanup(
    _fsp: *mut FspFileSystem,
    _fc: PVOID,
    _file_name: PWSTR,
    _flags: UINT32,
) {
    // No-op for read-only FS.
}

unsafe extern "system" fn cb_get_file_info(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    if fsp.is_null() || p_info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let fs = unsafe { get_fs(fsp) };
    let is_root = (fc as usize) == FC_ROOT;
    let is_file = (fc as usize) == FC_FILE;
    if !is_root && !is_file {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    unsafe {
        *p_info = if is_root {
            fs.file_info_dir
        } else {
            fs.file_info_file
        };
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn cb_read(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    buffer: PVOID,
    offset: UINT64,
    length: ULONG,
    p_bytes_transferred: PULONG,
) -> NTSTATUS {
    if fsp.is_null() || p_bytes_transferred.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        *p_bytes_transferred = 0;
    }
    if buffer.is_null() && length != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if length == 0 {
        return STATUS_SUCCESS;
    }
    let fs = unsafe { get_fs(fsp) };
    if (fc as usize) == FC_ROOT {
        return STATUS_NOT_A_DIRECTORY;
    }
    if (fc as usize) != FC_FILE {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if offset >= fs.manifest.total_plaintext_len {
        return STATUS_END_OF_FILE;
    }

    let out = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, length as usize) };

    let read_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_virtual(
            &fs.container_path,
            &fs.master_key,
            &fs.manifest,
            offset,
            out,
        )
    }));

    match read_res {
        Ok(Ok(n)) => {
            unsafe {
                *p_bytes_transferred = n as ULONG;
            }
            if n == 0 {
                STATUS_END_OF_FILE
            } else {
                STATUS_SUCCESS
            }
        }
        Ok(Err(e)) => {
            eprintln!("[obsidianq-fs] read error at offset {offset}: {e}");
            STATUS_ACCESS_DENIED
        }
        Err(_) => {
            eprintln!("[obsidianq-fs] panic in read callback at offset {offset}, length {length}");
            STATUS_ACCESS_DENIED
        }
    }
}

unsafe extern "system" fn cb_read_directory(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    _pattern: PWSTR,
    marker: PWSTR,
    buffer: PVOID,
    length: ULONG,
    p_bytes_transferred: PULONG,
) -> NTSTATUS {
    if fsp.is_null() || p_bytes_transferred.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        *p_bytes_transferred = 0;
    }
    if buffer.is_null() && length != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if (fc as usize) != FC_ROOT {
        return STATUS_NOT_A_DIRECTORY;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fs = unsafe { get_fs(fsp) };

        // WinFSP calls ReadDirectory repeatedly with a marker to paginate.
        // We have three entries: ".", "..", and the single decrypted file.
        // The marker is the last FileName returned in the previous batch.
        // WinFSP does NOT add "." or ".." automatically -- we must include them.
        let marker_str = if marker.is_null() {
            String::new()
        } else {
            unsafe { wchar_to_string(marker) }
        };
        let past_dot = !marker_str.is_empty();
        let past_dotdot = !marker_str.is_empty() && !marker_str.eq_ignore_ascii_case(".");
        let past_file = !marker_str.is_empty()
            && !marker_str.eq_ignore_ascii_case(".")
            && !marker_str.eq_ignore_ascii_case("..");

        // "." - root self-reference
        if !past_dot {
            let mut di = FspFsctlDirInfo::new(fs.file_info_dir, ".");
            let ok =
                unsafe { FspFileSystemAddDirInfo(&mut di, buffer, length, p_bytes_transferred) };
            if ok == 0 {
                return STATUS_SUCCESS;
            }
        }

        // ".." - parent (also root for a root directory)
        if !past_dotdot {
            let mut di = FspFsctlDirInfo::new(fs.file_info_dir, "..");
            let ok =
                unsafe { FspFileSystemAddDirInfo(&mut di, buffer, length, p_bytes_transferred) };
            if ok == 0 {
                return STATUS_SUCCESS;
            }
        }

        // The single decrypted file
        if !past_file {
            let mut di = FspFsctlDirInfo::new(fs.file_info_file, &fs.filename);
            let ok =
                unsafe { FspFileSystemAddDirInfo(&mut di, buffer, length, p_bytes_transferred) };
            if ok == 0 {
                return STATUS_SUCCESS;
            }
        }

        // Signal end of directory with a zero-size entry.
        unsafe {
            FspFileSystemAddDirInfo(std::ptr::null_mut(), buffer, length, p_bytes_transferred)
        };

        STATUS_SUCCESS
    }))
    .unwrap_or_else(|_| {
        eprintln!("[obsidianq-fs] panic in cb_read_directory");
        STATUS_ACCESS_DENIED
    })
}

/// Called by WinFSP when its I/O dispatcher thread pool stops.
/// `normally == 1` means we called FspFileSystemStopDispatcher ourselves.
/// `normally == 0` means WinFSP stopped unexpectedly (driver disconnect, etc.);
/// in that case we signal the stop event so the wait loop exits and cleans up.
unsafe extern "system" fn cb_dispatcher_stopped(fsp: *mut FspFileSystem, normally: BOOLEAN) {
    if normally != 0 {
        eprintln!("[obsidianq-fs] dispatcher stopped normally.");
        return;
    }
    eprintln!("[obsidianq-fs] dispatcher stopped ABNORMALLY - signaling stop event.");
    // Signal via the shared static so the main wait loop wakes and shuts down.
    use std::sync::atomic::Ordering;
    let h =
        crate::STOP_EVENT_HANDLE.load(Ordering::Relaxed) as windows_sys::Win32::Foundation::HANDLE;
    if !h.is_null() {
        unsafe {
            windows_sys::Win32::System::Threading::SetEvent(h);
        }
    } else if !fsp.is_null() {
        // Fallback: shouldn't happen, but log it.
        eprintln!("[obsidianq-fs] dispatcher stopped abnormally but stop handle is null.");
    }
}

/// All write/create/delete/rename operations -> STATUS_MEDIA_WRITE_PROTECTED.

unsafe extern "system" fn cb_flush(
    fsp: *mut FspFileSystem,
    fc: PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    if p_info.is_null() || fc.is_null() {
        return STATUS_SUCCESS;
    }
    cb_get_file_info(fsp, fc, p_info)
}

unsafe extern "system" fn cb_get_security(
    _fsp: *mut FspFileSystem,
    _fc: PVOID,
    _security_desc: PVOID,
    security_size: PSIZE_T,
) -> NTSTATUS {
    if !security_size.is_null() {
        unsafe {
            *security_size = 0;
        }
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn cb_write_denied(
    _fsp: *mut FspFileSystem,
    _fc: PVOID,
    _buf: PVOID,
    _off: UINT64,
    _len: ULONG,
    _eof: BOOLEAN,
    _cio: BOOLEAN,
    _bt: PULONG,
    _fi: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    STATUS_MEDIA_WRITE_PROTECTED
}

unsafe extern "system" fn cb_create_denied(
    _: *mut FspFileSystem,
    _: PWSTR,
    _: UINT32,
    _: UINT32,
    _: UINT32,
    _: PVOID,
    _: UINT64,
    _: *mut PVOID,
    _: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    STATUS_MEDIA_WRITE_PROTECTED
}

unsafe extern "system" fn cb_overwrite_denied(
    _: *mut FspFileSystem,
    _: PVOID,
    _: UINT32,
    _: BOOLEAN,
    _: UINT64,
    _: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    STATUS_MEDIA_WRITE_PROTECTED
}

unsafe extern "system" fn cb_rename_denied(
    _: *mut FspFileSystem,
    _: PVOID,
    _: PWSTR,
    _: PWSTR,
    _: BOOLEAN,
) -> NTSTATUS {
    STATUS_MEDIA_WRITE_PROTECTED
}

unsafe extern "system" fn cb_set_file_size_denied(
    _: *mut FspFileSystem,
    _: PVOID,
    _: UINT64,
    _: BOOLEAN,
    _: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    STATUS_MEDIA_WRITE_PROTECTED
}

unsafe extern "system" fn cb_set_basic_info_denied(
    _: *mut FspFileSystem,
    _: PVOID,
    _: UINT32,
    _: UINT64,
    _: UINT64,
    _: UINT64,
    _: UINT64,
    _: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    STATUS_MEDIA_WRITE_PROTECTED
}

unsafe extern "system" fn cb_can_delete_denied(
    _: *mut FspFileSystem,
    _: PVOID,
    _: PWSTR,
) -> NTSTATUS {
    STATUS_MEDIA_WRITE_PROTECTED
}

unsafe extern "system" fn cb_set_security_denied(
    _: *mut FspFileSystem,
    _: PVOID,
    _: UINT32,
    _: PVOID,
) -> NTSTATUS {
    STATUS_MEDIA_WRITE_PROTECTED
}

// ---------------------------------------------------------------------------
// Interface table - must be static (WinFSP holds a pointer to it).
// ---------------------------------------------------------------------------

static OBSQ_INTERFACE: FspFileSystemInterface = FspFileSystemInterface {
    get_volume_info: Some(cb_get_volume_info),
    set_volume_label: None,
    get_security_by_name: Some(cb_get_security_by_name),
    create: Some(cb_create_denied),
    open: Some(cb_open),
    overwrite: Some(cb_overwrite_denied),
    cleanup: Some(cb_cleanup),
    close: Some(cb_close),
    read: Some(cb_read),
    write: Some(cb_write_denied),
    flush: Some(cb_flush),
    get_file_info: Some(cb_get_file_info),
    set_basic_info: Some(cb_set_basic_info_denied),
    set_file_size: Some(cb_set_file_size_denied),
    can_delete: Some(cb_can_delete_denied),
    rename: Some(cb_rename_denied),
    get_security: Some(cb_get_security),
    set_security: Some(cb_set_security_denied),
    read_directory: Some(cb_read_directory),
    resolve_reparse_points: None,
    get_reparse_point: None,
    set_reparse_point: None,
    delete_reparse_point: None,
    get_stream_info: None,
    get_dir_info_by_name: None,
    control: None,
    set_delete: None,
    create_ex: None,
    overwrite_ex: None,
    get_ea: None,
    set_ea: None,
    obsolete0: None,
    dispatcher_stopped: Some(cb_dispatcher_stopped),
    _rest: [0usize; 31],
};

// ---------------------------------------------------------------------------
// Crash diagnostic filter
//
// Installed before FspFileSystemStartDispatcher.  Any unhandled SEH exception
// (access violation, stack overflow, etc.) in a WinFSP callback thread will
// call this filter, letting us log the exception code before the process dies.
//
// EXCEPTION_POINTERS layout (64-bit):
//   offset  0: *mut EXCEPTION_RECORD  (8 bytes)
//   offset  8: *mut CONTEXT           (8 bytes, unused)
//
// EXCEPTION_RECORD layout:
//   offset  0: ExceptionCode    u32
//   offset  4: ExceptionFlags   u32
//   offset  8: *mut EXCEPTION_RECORD (chained, unused)
//   offset 16: ExceptionAddress *mut c_void
// ---------------------------------------------------------------------------

unsafe extern "system" fn obsq_crash_filter(ep: *mut u8) -> i32 {
    use std::io::Write;
    if !ep.is_null() {
        // Read EXCEPTION_RECORD pointer from offset 0 of EXCEPTION_POINTERS.
        let er: *const u8 = unsafe { *(ep as *const *const u8) };
        if !er.is_null() {
            // ExceptionCode at offset 0 of EXCEPTION_RECORD.
            let code = unsafe { *(er as *const u32) };
            // ExceptionAddress at offset 16 of EXCEPTION_RECORD (after two u32s + one pointer).
            let addr_ptr = unsafe { er.add(16) };
            let addr = unsafe { *(addr_ptr as *const usize) };
            let _ = writeln!(
                std::io::stderr(),
                "[obsidianq-fs] CRASH: SEH exception code={code:#010x} addr={addr:#018x}"
            );
        } else {
            let _ = writeln!(
                std::io::stderr(),
                "[obsidianq-fs] CRASH: null ExceptionRecord"
            );
        }
    } else {
        let _ = writeln!(
            std::io::stderr(),
            "[obsidianq-fs] CRASH: null EXCEPTION_POINTERS"
        );
    }
    let _ = std::io::stderr().flush();
    0 // EXCEPTION_CONTINUE_SEARCH -- let Windows handle the crash normally
}

// ---------------------------------------------------------------------------
// Public mount / unmount API
// ---------------------------------------------------------------------------

/// Mount a verified `ContainerManifest` as a read-only virtual drive.
///
/// Blocks until `stop_event` is signalled (from `unmount_container`) or the
/// process receives SIGINT / Ctrl+C.
///
/// # Safety
/// This function is safe to call from Rust but internally uses FFI and raw
/// pointers as required by the WinFSP C API.
pub fn mount_container(
    container_path: &Path,
    master_key: MasterKey,
    manifest: ContainerManifest,
    drive_letter: char,
    stop_event: windows_sys::Win32::Foundation::HANDLE,
) -> Result<()> {
    let total = manifest.total_plaintext_len;

    // Build the volume params.
    let mut params = FspFsctlVolumeParams::new(total, "ObsidianQ");
    // Disable persistent ACLs - we serve our own security model.
    params.Flags &= !(1 << 3); // clear PersistentAcls

    let device_path = str_to_wchar_vec("WinFsp.Disk");
    let mount_point = str_to_wchar_vec(&format!("{drive_letter}:"));

    let mut fsp_ptr: *mut FspFileSystem = std::ptr::null_mut();

    let status = unsafe {
        FspFileSystemCreate(device_path.as_ptr(), &params, &OBSQ_INTERFACE, &mut fsp_ptr)
    };
    if status != STATUS_SUCCESS {
        if status == STATUS_NO_SUCH_DEVICE {
            return Err(FsError::WinFspDriverNotRunning);
        }
        return Err(FsError::WinFsp(status));
    }

    // Pin the ObsqFs on the heap and give WinFSP a pointer to it.
    // The Box lives until after `FspFileSystemStopDispatcher`.
    let fs_box = Box::new(ObsqFs::new(container_path, master_key, manifest));
    unsafe {
        FspFileSystemSetUserContext(fsp_ptr, Box::as_ref(&fs_box) as *const ObsqFs as PVOID);
    }

    // Install crash diagnostics: any unhandled SEH exception (access violation,
    // stack overflow, etc.) in a WinFSP callback thread will be logged by
    // obsq_crash_filter before the process terminates.
    unsafe {
        SetUnhandledExceptionFilter(Some(obsq_crash_filter));
    }

    // Set mount point (drive letter).
    let status = unsafe { FspFileSystemSetMountPoint(fsp_ptr, mount_point.as_ptr()) };
    if status != STATUS_SUCCESS {
        unsafe {
            FspFileSystemDelete(fsp_ptr);
        }
        return Err(FsError::WinFsp(status));
    }

    // Start the dispatcher (0 = let WinFSP choose thread count).
    let status = unsafe { FspFileSystemStartDispatcher(fsp_ptr, 0) };
    if status != STATUS_SUCCESS {
        unsafe {
            FspFileSystemDelete(fsp_ptr);
        }
        return Err(FsError::WinFsp(status));
    }

    println!("Mounted: {drive_letter}: (read-only)");
    println!("Press Ctrl+C or run 'obsidianq unmount --drive {drive_letter}:' to dismount.");

    // Block until the stop event is signalled (Ctrl+C or unmount command).
    unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(stop_event, 0xFFFFFFFF);
    }

    // Graceful shutdown.
    unsafe {
        FspFileSystemStopDispatcher(fsp_ptr);
    }
    unsafe {
        FspFileSystemDelete(fsp_ptr);
    }
    println!("Unmounted {drive_letter}:");
    // Drop the fs_box - this zeroizes the MasterKey via Arc drop.
    drop(fs_box);

    Ok(())
}
