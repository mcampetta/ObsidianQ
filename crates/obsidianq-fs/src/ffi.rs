//! Minimal WinFSP C API bindings.
//!
//! Only the functions and structures needed for a read-only single-file
//! virtual filesystem are declared here.  No attempt is made to wrap the
//! full WinFSP surface â€” add bindings as needed in future phases.
//!
//! WinFSP documentation: https://winfsp.dev/doc/WinFsp-API-Reference/
//! WinFSP headers       : <SDK>\inc\winfsp\winfsp.h
//! WinFSP source        : https://github.com/winfsp/winfsp

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::c_void;

// Windows primitive types used in WinFSP API.
pub type NTSTATUS = u32;
pub type ULONG    = u32;
pub type BOOLEAN  = u8;
pub type UINT16   = u16;
pub type UINT32   = u32;
pub type UINT64   = u64;
pub type PWSTR    = *const u16;
pub type PVOID    = *mut c_void;
pub type PULONG   = *mut u32;
pub type SIZE_T   = usize;
pub type PSIZE_T  = *mut usize;

// Sentinel NTSTATUS values.
pub const STATUS_SUCCESS:          NTSTATUS = 0x00000000;
pub const STATUS_ACCESS_DENIED:    NTSTATUS = 0xC0000022;
pub const STATUS_NOT_IMPLEMENTED:  NTSTATUS = 0xC0000002;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC0000034;
pub const STATUS_NOT_A_DIRECTORY:  NTSTATUS = 0xC0000103;
pub const STATUS_END_OF_FILE:      NTSTATUS = 0xC0000011;
pub const STATUS_MEDIA_WRITE_PROTECTED: NTSTATUS = 0xC00000A2;
pub const STATUS_NO_SUCH_DEVICE:        NTSTATUS = 0xC000000E;

// Windows file attribute constants.
pub const FILE_ATTRIBUTE_READONLY:  UINT32 = 0x00000001;
pub const FILE_ATTRIBUTE_DIRECTORY: UINT32 = 0x00000010;
pub const FILE_ATTRIBUTE_NORMAL:    UINT32 = 0x00000080;

// ---------------------------------------------------------------------------
// FSP_FSCTL_FILE_INFO (72 bytes)
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FspFsctlFileInfo {
    pub FileAttributes:   UINT32,
    pub ReparseTag:       UINT32,
    pub AllocationSize:   UINT64,
    pub FileSize:         UINT64,
    pub CreationTime:     UINT64,
    pub LastAccessTime:   UINT64,
    pub LastWriteTime:    UINT64,
    pub ChangeTime:       UINT64,
    pub IndexNumber:      UINT64,
    pub HardLinks:        UINT32,
    pub EaSize:           UINT32,
}

// ---------------------------------------------------------------------------
// FSP_FSCTL_VOLUME_INFO (80 bytes)
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Default)]
pub struct FspFsctlVolumeInfo {
    pub TotalSize:         UINT64,
    pub FreeSize:          UINT64,
    pub VolumeLabel:       [u16; 32],      // WCHAR[32]
}

// ---------------------------------------------------------------------------
// FSP_FSCTL_VOLUME_PARAMS (1024 bytes)
//
// Only the fields we actually need to set are named; the rest is packed as
// a raw byte array to achieve the correct total size.
// ---------------------------------------------------------------------------
#[repr(C)]
pub struct FspFsctlVolumeParams {
    pub Version:                    UINT16,     // 0
    pub SectorSize:                 UINT16,     // 2
    pub SectorsPerAllocationUnit:   UINT16,     // 4
    pub MaxComponentLength:         UINT16,     // 6
    pub VolumeCreationTime:         UINT64,     // 8
    pub VolumeSerialNumber:         UINT32,     // 16
    pub TransactTimeout:            UINT32,     // 20
    pub IrpTimeout:                 UINT32,     // 24
    pub IrpCapacity:                UINT32,     // 28
    pub FileInfoTimeout:            UINT32,     // 32
    /// Packed bit fields: CaseSensitiveSearch(0), CasePreservedNames(1),
    /// UnicodeOnDisk(2), PersistentAcls(3), ReparsePoints(4),
    /// ReparsePointsAccessCheck(5), NamedStreams(6), HardLinks(7),
    /// ExtendedAttributes(8), ReadOnlyVolume(9), ... (see winfsp.h)
    pub Flags:                      UINT32,     // 36
    pub TotalSize:                  UINT64,     // 40
    pub FreeSize:                   UINT64,     // 48
    pub Prefix:                     [u16; 192], // 56  (WCHAR[192] = 384 bytes)
    pub FileSystemName:             [u16; 16],  // 440 (WCHAR[16]  = 32 bytes)
    pub VolumeLabel:                [u16; 32],  // 472 (WCHAR[32]  = 64 bytes)
    _reserved:                      [u8; 488],  // 536 â†’ 1024 total
}

impl FspFsctlVolumeParams {
    pub fn new(total_bytes: u64, fs_name: &str) -> Self {
        let mut p = Self {
            Version:                  0,          // WinFSP fills this in
            SectorSize:               4096,
            SectorsPerAllocationUnit: 1,
            MaxComponentLength:       255,
            VolumeCreationTime:       unix_time_to_windows_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            VolumeSerialNumber:       0x4F425351u32, // "OBSQ" as u32
            TransactTimeout:          0,
            IrpTimeout:               0,
            IrpCapacity:              0,
            FileInfoTimeout:          1000,
            // CasePreservedNames (bit 1) | UnicodeOnDisk (bit 2) | ReadOnlyVolume (bit 9)
            Flags: (1 << 1) | (1 << 2) | (1 << 9),
            TotalSize:    total_bytes,
            FreeSize:     0,
            Prefix:       [0; 192],
            FileSystemName: [0; 16],
            VolumeLabel:  [0; 32],
            _reserved:    [0; 488],
        };
        str_to_wchar_fixed(fs_name, &mut p.FileSystemName);
        str_to_wchar_fixed("ObsidianQ", &mut p.VolumeLabel);
        p
    }
}

// ---------------------------------------------------------------------------
// FSP_FSCTL_DIR_INFO  (variable-length; we use a fixed-max-size version)
// Fixed header: Size(2) + FileInfo(72) + Pad(24) = 98 bytes
// Then FileName[N] follows immediately.
// ---------------------------------------------------------------------------
pub const DIR_INFO_HEADER_SIZE: usize = 2 + 72 + 24; // 98
pub const MAX_FILENAME_WCHARS:  usize = 260;          // MAX_PATH

#[repr(C)]
pub struct FspFsctlDirInfo {
    pub Size:     UINT16,                        // total struct size incl. FileName
    pub FileInfo: FspFsctlFileInfo,
    _pad:         [u8; 24],
    pub FileName: [u16; MAX_FILENAME_WCHARS],
}

impl FspFsctlDirInfo {
    pub fn new(info: FspFsctlFileInfo, name: &str) -> Self {
        let mut d = Self {
            Size:     0,
            FileInfo: info,
            _pad:     [0; 24],
            FileName: [0; MAX_FILENAME_WCHARS],
        };
        let n = str_to_wchar_fixed(name, &mut d.FileName);
        d.Size = (DIR_INFO_HEADER_SIZE + n * 2) as UINT16;
        d
    }
}

// ---------------------------------------------------------------------------
// FSP_FILE_SYSTEM
//
// Only the first two fields are named; the rest is accessed via WinFSP
// exported functions (SetMountPoint, StartDispatcher, etc.).
//
// Layout (64-bit, standard C alignment):
//   offset  0 : UINT16   Version
//   offset  2 : [u8; 6]  padding (to align PVOID to 8 bytes)
//   offset  8 : PVOID    UserContext
//   offset 16+: opaque remainder managed by WinFSP
// ---------------------------------------------------------------------------
#[repr(C)]
pub struct FspFileSystem {
    pub version:      u16,
    _pad:             [u8; 6],
    pub user_context: PVOID,
    _opaque:          [u8; 0],
}

// FspFileSystemGetUserContext / FspFileSystemSetUserContext are *inline*
// functions in winfsp.h that directly read/write the UserContext field.
// They are not exported by the DLL, so we implement them here in Rust.
pub unsafe fn FspFileSystemGetUserContext(fs: *mut FspFileSystem) -> PVOID {
    unsafe { (*fs).user_context }
}
pub unsafe fn FspFileSystemSetUserContext(fs: *mut FspFileSystem, ctx: PVOID) {
    unsafe { (*fs).user_context = ctx; }
}

// ---------------------------------------------------------------------------
// Function pointer types for the interface table
// ---------------------------------------------------------------------------
pub type GetVolumeInfoFn      = unsafe extern "system" fn(*mut FspFileSystem, *mut FspFsctlVolumeInfo) -> NTSTATUS;
pub type SetVolumeLabelFn     = unsafe extern "system" fn(*mut FspFileSystem, PWSTR, *mut FspFsctlVolumeInfo) -> NTSTATUS;
pub type GetSecurityByNameFn  = unsafe extern "system" fn(*mut FspFileSystem, PWSTR, *mut UINT32, PVOID, PSIZE_T) -> NTSTATUS;
pub type CreateFn             = unsafe extern "system" fn(*mut FspFileSystem, PWSTR, UINT32, UINT32, PVOID, UINT64, UINT32, *mut PVOID, *mut FspFsctlFileInfo) -> NTSTATUS;
pub type OpenFn               = unsafe extern "system" fn(*mut FspFileSystem, PWSTR, UINT32, UINT32, *mut PVOID, *mut FspFsctlFileInfo) -> NTSTATUS;
pub type OverwriteFn          = unsafe extern "system" fn(*mut FspFileSystem, PVOID, UINT32, BOOLEAN, UINT64, *mut FspFsctlFileInfo) -> NTSTATUS;
pub type CleanupFn            = unsafe extern "system" fn(*mut FspFileSystem, PVOID, PWSTR, UINT32);
pub type CloseFn              = unsafe extern "system" fn(*mut FspFileSystem, PVOID);
pub type ReadFn               = unsafe extern "system" fn(*mut FspFileSystem, PVOID, PVOID, UINT64, ULONG, PULONG) -> NTSTATUS;
pub type WriteFn              = unsafe extern "system" fn(*mut FspFileSystem, PVOID, PVOID, UINT64, ULONG, BOOLEAN, BOOLEAN, PULONG, *mut FspFsctlFileInfo) -> NTSTATUS;
pub type FlushFn              = unsafe extern "system" fn(*mut FspFileSystem, PVOID, *mut FspFsctlFileInfo) -> NTSTATUS;
pub type GetFileInfoFn        = unsafe extern "system" fn(*mut FspFileSystem, PVOID, *mut FspFsctlFileInfo) -> NTSTATUS;
pub type SetBasicInfoFn       = unsafe extern "system" fn(*mut FspFileSystem, PVOID, UINT32, UINT64, UINT64, UINT64, UINT64, *mut FspFsctlFileInfo) -> NTSTATUS;
pub type SetFileSizeFn        = unsafe extern "system" fn(*mut FspFileSystem, PVOID, UINT64, BOOLEAN, *mut FspFsctlFileInfo) -> NTSTATUS;
pub type CanDeleteFn          = unsafe extern "system" fn(*mut FspFileSystem, PVOID, PWSTR) -> NTSTATUS;
pub type RenameFn             = unsafe extern "system" fn(*mut FspFileSystem, PVOID, PWSTR, PWSTR, BOOLEAN) -> NTSTATUS;
pub type GetSecurityFn        = unsafe extern "system" fn(*mut FspFileSystem, PVOID, PVOID, PSIZE_T) -> NTSTATUS;
pub type SetSecurityFn        = unsafe extern "system" fn(*mut FspFileSystem, PVOID, UINT32, PVOID) -> NTSTATUS;
pub type ReadDirectoryFn      = unsafe extern "system" fn(*mut FspFileSystem, PVOID, PWSTR, PWSTR, PVOID, ULONG, PULONG) -> NTSTATUS;
// Remaining callbacks unused in Phase 1 â€” represented as *const c_void (NULL).

/// The interface (function pointer) table.  Must be `#[repr(C)]` and match
/// `FSP_FILE_SYSTEM_INTERFACE` in `winfsp.h` exactly.
///
/// Unused slots (reparsepoints, streams, EA, etc.) are NULL.
/// WinFSP treats NULL callbacks as "not supported" and returns
/// STATUS_INVALID_DEVICE_REQUEST automatically.
#[repr(C)]
pub struct FspFileSystemInterface {
    pub get_volume_info:      Option<GetVolumeInfoFn>,
    pub set_volume_label:     Option<SetVolumeLabelFn>,
    pub get_security_by_name: Option<GetSecurityByNameFn>,
    pub create:               Option<CreateFn>,
    pub open:                 Option<OpenFn>,
    pub overwrite:            Option<OverwriteFn>,
    pub cleanup:              Option<CleanupFn>,
    pub close:                Option<CloseFn>,
    pub read:                 Option<ReadFn>,
    pub write:                Option<WriteFn>,
    pub flush:                Option<FlushFn>,
    pub get_file_info:        Option<GetFileInfoFn>,
    pub set_basic_info:       Option<SetBasicInfoFn>,
    pub set_file_size:        Option<SetFileSizeFn>,
    pub can_delete:           Option<CanDeleteFn>,
    pub rename:               Option<RenameFn>,
    pub get_security:         Option<GetSecurityFn>,
    pub set_security:         Option<SetSecurityFn>,
    pub read_directory:       Option<ReadDirectoryFn>,
    // Remaining 12 named callbacks (ResolveReparsePoints..SetEa) +
    // Reserved words = 45 u64-sized slots.
    // C struct total: 64 function pointers * 8 = 512 bytes on x64.
    pub _rest: [u64; 45],
}

// ---------------------------------------------------------------------------
// WinFSP exported functions
// ---------------------------------------------------------------------------
#[cfg(feature = "winfsp")]
#[link(name = "winfsp-x64", kind = "dylib")]
extern "system" {
    pub fn FspFileSystemCreate(
        DevicePath:   PWSTR,
        VolumeParams: *const FspFsctlVolumeParams,
        Interface:    *const FspFileSystemInterface,
        PFileSystem:  *mut *mut FspFileSystem,
    ) -> NTSTATUS;

    pub fn FspFileSystemDelete(FileSystem: *mut FspFileSystem);

    pub fn FspFileSystemSetMountPoint(
        FileSystem:  *mut FspFileSystem,
        MountPoint:  PWSTR,
    ) -> NTSTATUS;

    pub fn FspFileSystemStartDispatcher(
        FileSystem:   *mut FspFileSystem,
        ThreadCount:  ULONG,
    ) -> NTSTATUS;

    pub fn FspFileSystemStopDispatcher(FileSystem: *mut FspFileSystem);

    /// Add a dir-info entry to the read-directory buffer.
    /// Returns FALSE when the buffer is full (caller should stop and return
    /// the partial result; WinFSP will call ReadDirectory again with a marker).
    pub fn FspFileSystemAddDirInfo(
        DirInfo:           *mut FspFsctlDirInfo,
        Buffer:            PVOID,
        Length:            ULONG,
        PBytesTransferred: PULONG,
    ) -> BOOLEAN;

    /// Convert a Win32 error code to an NTSTATUS.
    pub fn FspNtStatusFromWin32(Error: UINT32) -> NTSTATUS;
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Write `s` as UTF-16LE into `buf`, null-terminate.  Returns the number of
/// WCHAR code units written (including null terminator).
pub fn str_to_wchar_fixed(s: &str, buf: &mut [u16]) -> usize {
    let mut n = 0;
    for (i, c) in s.encode_utf16().enumerate() {
        if i + 1 >= buf.len() { break; }
        buf[i] = c;
        n = i + 1;
    }
    if n < buf.len() { buf[n] = 0; n += 1; }
    n
}

/// Allocate a null-terminated UTF-16 string on the heap.
pub fn str_to_wchar_vec(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// Read a null-terminated UTF-16 string from a raw PWSTR.
///
/// # Safety
/// `ptr` must point to a valid null-terminated UTF-16 string.
pub unsafe fn wchar_to_string(ptr: PWSTR) -> String {
    if ptr.is_null() { return String::new(); }
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 { len += 1; }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

/// Convert Unix timestamp (seconds) to Windows FILETIME (100-ns intervals
/// since 1601-01-01).
pub fn unix_time_to_windows_time(unix_secs: u64) -> UINT64 {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000; // 100-ns intervals
    unix_secs * 10_000_000 + EPOCH_DIFF
}

/// Return the current time as a Windows FILETIME.
pub fn now_windows_time() -> UINT64 {
    unix_time_to_windows_time(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}
