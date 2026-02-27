//! WinFSP virtual filesystem implementation for ObsidianQ containers.
//!
//! Exposes a single decrypted file under the virtual drive root.
//! All write operations return STATUS_MEDIA_WRITE_PROTECTED.
//!
//! SAFETY NOTES:
//! - `ObsqFs` is pinned in a `Box` before its raw pointer is given to WinFSP.
//!   The Box is kept alive for the lifetime of the mount.
//! - `FileContext` pointers passed through WinFSP's PVOID FileContext are
//!   allocated via `Box::into_raw` and freed in the `close` callback via
//!   `Box::from_raw`.  WinFSP guarantees that close is always called after open.
//! - All accesses to `ObsqFs` fields from callbacks are via shared references
//!   (no mutation after construction), making the impl Send + Sync safe.

#![allow(non_snake_case)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use obsidianq_core::{ContainerManifest, crypto::kdf::MasterKey};

use crate::chunk_io::read_virtual;
use crate::error::{FsError, Result};
use crate::ffi::*;

// ---------------------------------------------------------------------------
// File context passed through WinFSP's PVOID FileContext
// ---------------------------------------------------------------------------

/// Indicates whether the open context represents the root directory or the
/// single exposed file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FcKind { Root, File }

struct FileContext {
    kind: FcKind,
}

// ---------------------------------------------------------------------------
// The main filesystem state (one instance per mount)
// ---------------------------------------------------------------------------

pub struct ObsqFs {
    container_path: PathBuf,
    master_key:     Arc<MasterKey>,   // Arc so the key outlives any WinFSP threads
    manifest:       Arc<ContainerManifest>,
    filename:       String,           // virtual filename (basename without .obsq)
    file_info_file: FspFsctlFileInfo, // pre-built FileInfo for the single file
    file_info_dir:  FspFsctlFileInfo, // pre-built FileInfo for the root dir
}

impl ObsqFs {
    pub fn new(
        container_path: &Path,
        master_key:     MasterKey,
        manifest:       ContainerManifest,
    ) -> Self {
        let filename = container_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decrypted")
            .to_owned();

        let now   = now_windows_time();
        let fsize = manifest.total_plaintext_len;
        let chunk = manifest.header.chunk_size as u64;
        let alloc = ((fsize + chunk - 1) / chunk) * chunk;

        let file_info_file = FspFsctlFileInfo {
            FileAttributes:  FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL,
            ReparseTag:      0,
            AllocationSize:  alloc,
            FileSize:        fsize,
            CreationTime:    now,
            LastAccessTime:  now,
            LastWriteTime:   now,
            ChangeTime:      now,
            IndexNumber:     2, // 1 = root, 2 = the file
            HardLinks:       1,
            EaSize:          0,
        };
        let file_info_dir = FspFsctlFileInfo {
            FileAttributes:  FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY,
            ReparseTag:      0,
            AllocationSize:  0,
            FileSize:        0,
            CreationTime:    now,
            LastAccessTime:  now,
            LastWriteTime:   now,
            ChangeTime:      now,
            IndexNumber:     1,
            HardLinks:       1,
            EaSize:          0,
        };

        ObsqFs {
            container_path: container_path.to_owned(),
            master_key:     Arc::new(master_key),
            manifest:       Arc::new(manifest),
            filename,
            file_info_file,
            file_info_dir,
        }
    }

    /// Path matching: "/" and "" = root directory; "/filename" = the file.
    fn classify_path(&self, raw_path: PWSTR) -> Option<FcKind> {
        let path = unsafe { wchar_to_string(raw_path) };
        let path = path.replace('\\', "/");
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            Some(FcKind::Root)
        } else if trimmed.eq_ignore_ascii_case(&self.filename) {
            Some(FcKind::File)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// WinFSP callback trampolines
//
// Each callback:
//   1. Recovers `&ObsqFs` from the WinFSP UserContext.
//   2. Does the work.
//   3. Returns an NTSTATUS.
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
    fsp:  *mut FspFileSystem,
    info: *mut FspFsctlVolumeInfo,
) -> NTSTATUS {
    let fs = unsafe { get_fs(fsp) };
    let out = unsafe { &mut *info };
    out.TotalSize = fs.manifest.total_plaintext_len;
    out.FreeSize  = 0;
    str_to_wchar_fixed("ObsidianQ", &mut out.VolumeLabel);
    STATUS_SUCCESS
}

unsafe extern "system" fn cb_get_security_by_name(
    fsp:             *mut FspFileSystem,
    file_name:       PWSTR,
    p_file_attrs:    *mut UINT32,
    _security_desc:  PVOID,
    security_size:   PSIZE_T,
) -> NTSTATUS {
    let fs = unsafe { get_fs(fsp) };
    if !security_size.is_null() {
        unsafe { *security_size = 0; }
    }
    match fs.classify_path(file_name) {
        Some(FcKind::Root) => {
            if !p_file_attrs.is_null() {
                unsafe { *p_file_attrs = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY; }
            }
            STATUS_SUCCESS
        }
        Some(FcKind::File) => {
            if !p_file_attrs.is_null() {
                unsafe { *p_file_attrs = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL; }
            }
            STATUS_SUCCESS
        }
        None => STATUS_OBJECT_NAME_NOT_FOUND,
    }
}

unsafe extern "system" fn cb_open(
    fsp:           *mut FspFileSystem,
    file_name:     PWSTR,
    _create_opts:  UINT32,
    _granted:      UINT32,
    p_fc:          *mut PVOID,
    p_info:        *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let fs = unsafe { get_fs(fsp) };
    match fs.classify_path(file_name) {
        Some(kind) => {
            let fc  = Box::new(FileContext { kind });
            unsafe { *p_fc = Box::into_raw(fc) as PVOID; }
            unsafe { *p_info = if kind == FcKind::Root { fs.file_info_dir } else { fs.file_info_file }; }
            STATUS_SUCCESS
        }
        None => STATUS_OBJECT_NAME_NOT_FOUND,
    }
}

unsafe extern "system" fn cb_close(
    _fsp: *mut FspFileSystem,
    fc:   PVOID,
) {
    if !fc.is_null() {
        // Reclaim the Box and drop the FileContext.
        let _ = unsafe { Box::from_raw(fc as *mut FileContext) };
    }
}

unsafe extern "system" fn cb_cleanup(
    _fsp:       *mut FspFileSystem,
    _fc:        PVOID,
    _file_name: PWSTR,
    _flags:     UINT32,
) { /* No-op for read-only FS */ }

unsafe extern "system" fn cb_get_file_info(
    fsp:    *mut FspFileSystem,
    fc:     PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    let fs = unsafe { get_fs(fsp) };
    if fc.is_null() { return STATUS_OBJECT_NAME_NOT_FOUND; }
    let ctx = unsafe { &*(fc as *const FileContext) };
    unsafe { *p_info = if ctx.kind == FcKind::Root { fs.file_info_dir } else { fs.file_info_file }; }
    STATUS_SUCCESS
}

unsafe extern "system" fn cb_read(
    fsp:                *mut FspFileSystem,
    fc:                 PVOID,
    buffer:             PVOID,
    offset:             UINT64,
    length:             ULONG,
    p_bytes_transferred: PULONG,
) -> NTSTATUS {
    let fs = unsafe { get_fs(fsp) };
    if fc.is_null() { return STATUS_OBJECT_NAME_NOT_FOUND; }
    let ctx = unsafe { &*(fc as *const FileContext) };
    if ctx.kind == FcKind::Root { return STATUS_NOT_A_DIRECTORY; }

    if offset >= fs.manifest.total_plaintext_len {
        unsafe { *p_bytes_transferred = 0; }
        return STATUS_END_OF_FILE;
    }

    let out = unsafe {
        std::slice::from_raw_parts_mut(buffer as *mut u8, length as usize)
    };

    match read_virtual(&fs.container_path, &fs.master_key, &fs.manifest, offset, out) {
        Ok(n) => {
            unsafe { *p_bytes_transferred = n as ULONG; }
            if n == 0 { STATUS_END_OF_FILE } else { STATUS_SUCCESS }
        }
        Err(e) => {
            eprintln!("[obsidianq-fs] read error at offset {offset}: {e}");
            STATUS_ACCESS_DENIED
        }
    }
}

unsafe extern "system" fn cb_read_directory(
    fsp:                 *mut FspFileSystem,
    fc:                  PVOID,
    _pattern:            PWSTR,
    marker:              PWSTR,
    buffer:              PVOID,
    length:              ULONG,
    p_bytes_transferred: PULONG,
) -> NTSTATUS {
    let fs = unsafe { get_fs(fsp) };
    if fc.is_null() { return STATUS_OBJECT_NAME_NOT_FOUND; }
    let ctx = unsafe { &*(fc as *const FileContext) };
    if ctx.kind != FcKind::Root { return STATUS_NOT_A_DIRECTORY; }

    // WinFSP calls ReadDirectory repeatedly with a marker to paginate.
    // We have only two entries: "." and one file.
    // The marker is the last FileName returned in the previous batch.
    let marker_str = if marker.is_null() {
        String::new()
    } else {
        unsafe { wchar_to_string(marker) }
    };
    let past_dot    = !marker_str.is_empty();
    let past_file   = !marker_str.is_empty()
        && !marker_str.eq_ignore_ascii_case(".");

    // "." Ã¢â‚¬â€ root self-reference
    if !past_dot {
        let mut di = FspFsctlDirInfo::new(fs.file_info_dir, ".");
        let ok = unsafe {
            FspFileSystemAddDirInfo(&mut di, buffer, length, p_bytes_transferred)
        };
        if ok == 0 { return STATUS_SUCCESS; }
    }

    // The single decrypted file
    if !past_file {
        let mut di = FspFsctlDirInfo::new(fs.file_info_file, &fs.filename);
        unsafe { FspFileSystemAddDirInfo(&mut di, buffer, length, p_bytes_transferred) };
    }

    // Signal end of directory with a zero-size entry.
    unsafe {
        FspFileSystemAddDirInfo(
            std::ptr::null_mut(),
            buffer,
            length,
            p_bytes_transferred,
        )
    };

    STATUS_SUCCESS
}

/// All write/create/delete/rename operations Ã¢â€ â€™ STATUS_MEDIA_WRITE_PROTECTED.

unsafe extern "system" fn cb_flush(
    fsp:    *mut FspFileSystem,
    fc:     PVOID,
    p_info: *mut FspFsctlFileInfo,
) -> NTSTATUS {
    if p_info.is_null() || fc.is_null() {
        return STATUS_SUCCESS;
    }
    cb_get_file_info(fsp, fc, p_info)
}

unsafe extern "system" fn cb_get_security(
    _fsp:           *mut FspFileSystem,
    _fc:            PVOID,
    _security_desc: PVOID,
    security_size:  PSIZE_T,
) -> NTSTATUS {
    if !security_size.is_null() {
        unsafe { *security_size = 0; }
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn cb_write_denied(
    _fsp: *mut FspFileSystem,
    _fc:  PVOID,
    _buf: PVOID,
    _off: UINT64,
    _len: ULONG,
    _eof: BOOLEAN,
    _cio: BOOLEAN,
    _bt:  PULONG,
    _fi:  *mut FspFsctlFileInfo,
) -> NTSTATUS { STATUS_MEDIA_WRITE_PROTECTED }

unsafe extern "system" fn cb_create_denied(
    _: *mut FspFileSystem, _: PWSTR, _: UINT32, _: UINT32, _: PVOID,
    _: UINT64, _: UINT32, _: *mut PVOID, _: *mut FspFsctlFileInfo,
) -> NTSTATUS { STATUS_MEDIA_WRITE_PROTECTED }

unsafe extern "system" fn cb_overwrite_denied(
    _: *mut FspFileSystem, _: PVOID, _: UINT32, _: BOOLEAN, _: UINT64, _: *mut FspFsctlFileInfo,
) -> NTSTATUS { STATUS_MEDIA_WRITE_PROTECTED }

unsafe extern "system" fn cb_rename_denied(
    _: *mut FspFileSystem, _: PVOID, _: PWSTR, _: PWSTR, _: BOOLEAN,
) -> NTSTATUS { STATUS_MEDIA_WRITE_PROTECTED }

unsafe extern "system" fn cb_set_file_size_denied(
    _: *mut FspFileSystem, _: PVOID, _: UINT64, _: BOOLEAN, _: *mut FspFsctlFileInfo,
) -> NTSTATUS { STATUS_MEDIA_WRITE_PROTECTED }

unsafe extern "system" fn cb_set_basic_info_denied(
    _: *mut FspFileSystem, _: PVOID, _: UINT32,
    _: UINT64, _: UINT64, _: UINT64, _: UINT64, _: *mut FspFsctlFileInfo,
) -> NTSTATUS { STATUS_MEDIA_WRITE_PROTECTED }

unsafe extern "system" fn cb_can_delete_denied(
    _: *mut FspFileSystem, _: PVOID, _: PWSTR,
) -> NTSTATUS { STATUS_MEDIA_WRITE_PROTECTED }

unsafe extern "system" fn cb_set_security_denied(
    _: *mut FspFileSystem, _: PVOID, _: UINT32, _: PVOID,
) -> NTSTATUS { STATUS_MEDIA_WRITE_PROTECTED }


// ---------------------------------------------------------------------------
// Interface table Ã¢â‚¬â€ must be static (WinFSP holds a pointer to it).
// ---------------------------------------------------------------------------

static OBSQ_INTERFACE: FspFileSystemInterface = FspFileSystemInterface {
    get_volume_info:      Some(cb_get_volume_info),
    set_volume_label:     None,
    get_security_by_name: Some(cb_get_security_by_name),
    create:               Some(cb_create_denied),
    open:                 Some(cb_open),
    overwrite:            Some(cb_overwrite_denied),
    cleanup:              Some(cb_cleanup),
    close:                Some(cb_close),
    read:                 Some(cb_read),
    write:                Some(cb_write_denied),
    flush:                Some(cb_flush),
    get_file_info:        Some(cb_get_file_info),
    set_basic_info:       Some(cb_set_basic_info_denied),
    set_file_size:        Some(cb_set_file_size_denied),
    can_delete:           Some(cb_can_delete_denied),
    rename:               Some(cb_rename_denied),
    get_security:         Some(cb_get_security),
    set_security:         Some(cb_set_security_denied),
    read_directory:       Some(cb_read_directory),
    _rest:                [0u64; 45],
};

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
    master_key:     MasterKey,
    manifest:       ContainerManifest,
    drive_letter:   char,
    stop_event:     windows_sys::Win32::Foundation::HANDLE,
) -> Result<()> {
    let total = manifest.total_plaintext_len;

    // Build the volume params.
    let mut params = FspFsctlVolumeParams::new(total, "ObsidianQ");
    // Disable persistent ACLs Ã¢â‚¬â€ we serve our own security model.
    params.Flags &= !(1 << 3); // clear PersistentAcls

    // Wide-string device path for WinFSP user-mode filesystem.
    // FSP_FSCTL_DISK_DEVICE_NAME from winfsp.h = "WinFsp.Disk"
    let device_path = str_to_wchar_vec("WinFsp.Disk");
    let mount_point  = str_to_wchar_vec(&format!("{drive_letter}:"));

    let mut fsp_ptr: *mut FspFileSystem = std::ptr::null_mut();

    let status = unsafe {
        FspFileSystemCreate(
            device_path.as_ptr(),
            &params,
            &OBSQ_INTERFACE,
            &mut fsp_ptr,
        )
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

    // Set mount point (drive letter).
    let status = unsafe { FspFileSystemSetMountPoint(fsp_ptr, mount_point.as_ptr()) };
    if status != STATUS_SUCCESS {
        unsafe { FspFileSystemDelete(fsp_ptr); }
        return Err(FsError::WinFsp(status));
    }

    // Start the dispatcher (0 = let WinFSP choose thread count).
    let status = unsafe { FspFileSystemStartDispatcher(fsp_ptr, 0) };
    if status != STATUS_SUCCESS {
        unsafe { FspFileSystemDelete(fsp_ptr); }
        return Err(FsError::WinFsp(status));
    }

    println!("Mounted: {drive_letter}: (read-only)");
    println!("Press Ctrl+C or run 'obsidianq unmount --drive {drive_letter}:' to dismount.");

    // Block until the stop event is signalled or Ctrl+C.
    unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(
            stop_event,
            windows_sys::Win32::System::Threading::INFINITE,
        );
    }

    // Graceful shutdown.
    unsafe { FspFileSystemStopDispatcher(fsp_ptr); }
    unsafe { FspFileSystemDelete(fsp_ptr); }

    // Drop the fs_box Ã¢â‚¬â€ this zeroizes the MasterKey via Arc drop.
    drop(fs_box);

    Ok(())
}

