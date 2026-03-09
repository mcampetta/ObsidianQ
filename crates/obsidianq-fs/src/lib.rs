//! `obsidianq-fs` -- virtual filesystem layer for ObsidianQ containers.
//!
//! ## Enabling WinFSP mount support
//! Build with `--features winfsp` and ensure the WinFSP SDK is installed:
//!   https://github.com/winfsp/winfsp/releases
//!
//! Without the feature, `mount_container` and `unmount_container` return
//! `Err(FsError::WinFspNotInstalled)`.
//!
//! ## Usage
//! ```no_run
//! use obsidianq_fs::{mount_container, unmount_container, MountOptions};
//! ```

pub mod chunk_io;
pub mod error;
pub mod ffi;
pub mod manifest;

#[cfg(feature = "winfsp")]
mod vfs;

#[cfg(feature = "winfsp")]
pub mod vault_vfs;

pub use error::{FsError, Result};
pub use manifest::{chunk_inner_offset, chunks_for_range};

use obsidianq_core::{crypto::kdf::MasterKey, ContainerManifest};
use std::path::Path;

// ---------------------------------------------------------------------------
// Named-event IPC for cross-process unmount
// ---------------------------------------------------------------------------
//
// When `mount_container` is running in foreground, a named Windows event
//   Global\ObsidianQ_Mount_{LETTER}
// is created.  `unmount_container` opens and signals the same event.
// The mount loop waits on this event (alongside Ctrl+C).

#[cfg(feature = "winfsp")]
fn stop_event_name(drive: char) -> Vec<u16> {
    ffi::str_to_wchar_vec(&format!(
        "Global\\ObsidianQ_Mount_{}",
        drive.to_ascii_uppercase()
    ))
}

#[cfg(feature = "winfsp")]
fn vault_stop_event_name(drive: char) -> Vec<u16> {
    ffi::str_to_wchar_vec(&format!(
        "Global\\ObsidianQ_VaultMount_{}",
        drive.to_ascii_uppercase()
    ))
}

// ---------------------------------------------------------------------------
// Public mount API
// ---------------------------------------------------------------------------

/// Options for mounting a container.
pub struct MountOptions {
    /// Path to the `.obsq` container file.
    pub container_path: std::path::PathBuf,
    /// Drive letter (A - Z).
    pub drive_letter: char,
}

/// Mount `container_path` as a read-only virtual drive at `drive_letter:`.
///
/// Blocks until Ctrl+C is pressed or `unmount_container` is called for the
/// same drive letter.  The master key is zeroized on unmount.
///
/// Requires the `winfsp` feature and WinFSP runtime installed.
pub fn mount_container(
    container_path: &Path,
    master_key: MasterKey,
    manifest: ContainerManifest,
    drive_letter: char,
) -> Result<()> {
    let dl = drive_letter.to_ascii_uppercase();
    if !('A'..='Z').contains(&dl) {
        return Err(FsError::InvalidDriveLetter(drive_letter.to_string()));
    }

    #[cfg(feature = "winfsp")]
    {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
            System::Threading::{CreateEventW, ResetEvent},
        };

        // Create the named event that unmount will signal.
        let event_name = stop_event_name(dl);
        let stop_event = unsafe {
            CreateEventW(
                std::ptr::null(),
                1, // manual reset
                0, // not signalled
                event_name.as_ptr(),
            )
        };
        if stop_event == INVALID_HANDLE_VALUE || stop_event == std::ptr::null_mut() {
            return Err(FsError::Io(std::io::Error::last_os_error()));
        }

        // If the named event already existed and was left signaled by a prior
        // unmount request, clear it so this mount session does not auto-exit.
        unsafe {
            ResetEvent(stop_event);
        }

        // Wire up Ctrl+C to signal the stop event.
        ctrlc_setup(stop_event);

        let result = vfs::mount_container(container_path, master_key, manifest, dl, stop_event);

        unsafe {
            CloseHandle(stop_event);
        }
        result
    }

    #[cfg(not(feature = "winfsp"))]
    {
        let _ = (container_path, master_key, manifest, dl);
        Err(FsError::WinFspNotInstalled)
    }
}

/// Signal a running `mount_container` to stop and unmount `drive_letter:`.
///
/// Works by opening and signalling the named event created by `mount_container`.
pub fn unmount_container(drive_letter: char) -> Result<()> {
    let dl = drive_letter.to_ascii_uppercase();
    if !('A'..='Z').contains(&dl) {
        return Err(FsError::InvalidDriveLetter(drive_letter.to_string()));
    }

    #[cfg(feature = "winfsp")]
    {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
            System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE},
        };

        let event_name = stop_event_name(dl);
        let h = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, event_name.as_ptr()) };
        if h == INVALID_HANDLE_VALUE || h == std::ptr::null_mut() {
            return Err(FsError::NotMounted(dl));
        }
        unsafe {
            SetEvent(h);
        }
        unsafe {
            CloseHandle(h);
        }
        println!("Unmount signal sent to {dl}:");
        Ok(())
    }

    #[cfg(not(feature = "winfsp"))]
    {
        let _ = dl;
        Err(FsError::WinFspNotInstalled)
    }
}

// ---------------------------------------------------------------------------
// Vault mount / unmount API
// ---------------------------------------------------------------------------

/// Mount a `.vault` vault at `drive_letter:` (read/write).
///
/// Blocks until Ctrl+C or `unmount_vault` is called for the same drive letter.
///
/// Requires the `winfsp` feature and WinFSP runtime installed.
pub fn mount_vault(
    vault_path: &std::path::Path,
    master_key: MasterKey,
    drive_letter: char,
    log_path: Option<&std::path::Path>,
    volparams_version: u16,
) -> Result<()> {
    let dl = drive_letter.to_ascii_uppercase();
    if !('A'..='Z').contains(&dl) {
        return Err(FsError::InvalidDriveLetter(drive_letter.to_string()));
    }

    #[cfg(feature = "winfsp")]
    {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
            System::Threading::{CreateEventW, ResetEvent},
        };

        let event_name = vault_stop_event_name(dl);
        let stop_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, event_name.as_ptr()) };
        if stop_event == INVALID_HANDLE_VALUE || stop_event == std::ptr::null_mut() {
            return Err(FsError::Io(std::io::Error::last_os_error()));
        }
        unsafe {
            ResetEvent(stop_event);
        }

        ctrlc_setup(stop_event);

        let result = vault_vfs::mount_vault(
            vault_path,
            master_key,
            dl,
            stop_event,
            log_path,
            volparams_version,
        );

        unsafe {
            CloseHandle(stop_event);
        }
        result
    }

    #[cfg(not(feature = "winfsp"))]
    {
        let _ = (vault_path, master_key, dl, log_path, volparams_version);
        Err(FsError::WinFspNotInstalled)
    }
}

/// Mount a diagnostic mock filesystem at `drive_letter:`.
///
/// The volume contains a single `/hello.txt` file.  Use this to verify that
/// the WinFSP callback wiring works independently of vault I/O.
pub fn mount_vault_mock(
    drive_letter: char,
    log_path: Option<&std::path::Path>,
    volparams_version: u16,
) -> Result<()> {
    let dl = drive_letter.to_ascii_uppercase();
    if !('A'..='Z').contains(&dl) {
        return Err(FsError::InvalidDriveLetter(drive_letter.to_string()));
    }

    #[cfg(feature = "winfsp")]
    {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
            System::Threading::{CreateEventW, ResetEvent},
        };

        // Reuse the vault stop-event namespace so `unmount_vault` signals it.
        let event_name = vault_stop_event_name(dl);
        let stop_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, event_name.as_ptr()) };
        if stop_event == INVALID_HANDLE_VALUE || stop_event == std::ptr::null_mut() {
            return Err(FsError::Io(std::io::Error::last_os_error()));
        }
        unsafe {
            ResetEvent(stop_event);
        }

        ctrlc_setup(stop_event);

        let result = vault_vfs::mount_vault_mock(dl, stop_event, log_path, volparams_version);

        unsafe {
            CloseHandle(stop_event);
        }
        result
    }

    #[cfg(not(feature = "winfsp"))]
    {
        let _ = (dl, log_path, volparams_version);
        Err(FsError::WinFspNotInstalled)
    }
}

/// Signal a running `mount_vault` to stop and unmount `drive_letter:`.
pub fn unmount_vault(drive_letter: char) -> Result<()> {
    let dl = drive_letter.to_ascii_uppercase();
    if !('A'..='Z').contains(&dl) {
        return Err(FsError::InvalidDriveLetter(drive_letter.to_string()));
    }

    #[cfg(feature = "winfsp")]
    {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
            System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE},
        };

        let event_name = vault_stop_event_name(dl);
        let h = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, event_name.as_ptr()) };
        if h == INVALID_HANDLE_VALUE || h == std::ptr::null_mut() {
            return Err(FsError::NotMounted(dl));
        }
        unsafe {
            SetEvent(h);
        }
        unsafe {
            CloseHandle(h);
        }
        println!("Unmount signal sent to vault at {dl}:");
        Ok(())
    }

    #[cfg(not(feature = "winfsp"))]
    {
        let _ = dl;
        Err(FsError::WinFspNotInstalled)
    }
}

// ---------------------------------------------------------------------------
// Ctrl+C handler
// ---------------------------------------------------------------------------

#[cfg(feature = "winfsp")]
// Store the stop-event handle in a static so the Ctrl+C callback and the
// dispatcher_stopped callback can reach it.
// isize is the same size as HANDLE on all supported Windows targets.
pub(crate) static STOP_EVENT_HANDLE: std::sync::atomic::AtomicIsize =
    std::sync::atomic::AtomicIsize::new(0);

#[cfg(feature = "winfsp")]
fn ctrlc_setup(event: windows_sys::Win32::Foundation::HANDLE) {
    use std::sync::atomic::Ordering;
    use std::sync::Once;
    static INIT: Once = Once::new();

    STOP_EVENT_HANDLE.store(event as isize, Ordering::Relaxed);
    INIT.call_once(|| unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    });
}

#[cfg(feature = "winfsp")]
unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> windows_sys::Win32::Foundation::BOOL {
    // Only handle Ctrl+C (0) and Ctrl+Break (1).
    // CTRL_CLOSE_EVENT (2), CTRL_LOGOFF_EVENT (5), CTRL_SHUTDOWN_EVENT (6)
    // must not signal stop - return FALSE so Windows applies default behavior.
    if ctrl_type > 1 {
        return 0; // FALSE - not handled
    }
    use std::sync::atomic::Ordering;
    let h = STOP_EVENT_HANDLE.load(Ordering::Relaxed) as windows_sys::Win32::Foundation::HANDLE;
    if !h.is_null() {
        let name = if ctrl_type == 0 { "C" } else { "Break" };
        eprintln!("[obsidianq-fs] Ctrl+{name} received, signaling stop event.");
        unsafe {
            windows_sys::Win32::System::Threading::SetEvent(h);
        }
    }
    1 // TRUE - handled
}

// ---------------------------------------------------------------------------
// WinFSP installation check (used by CLI for helpful error messages)
// ---------------------------------------------------------------------------

/// Returns `true` if WinFSP appears to be installed (DLL is loadable).
///
/// This is a best-effort runtime check.  Always returns `false` when the
/// `winfsp` feature is disabled.
pub fn is_winfsp_available() -> bool {
    #[cfg(feature = "winfsp")]
    {
        use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

        // Try the bare name first (works if the WinFSP bin dir is in PATH),
        // then fall back to the two default install locations.
        // Intentionally not calling FreeLibrary -- one-time check; keeping the
        // handle loaded avoids a reload cycle on the first mount call.
        let candidates = [
            "winfsp-x64.dll",
            r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll",
            r"C:\Program Files\WinFsp\bin\winfsp-x64.dll",
        ];
        candidates.iter().any(|path| {
            let wide = ffi::str_to_wchar_vec(path);
            !unsafe { LoadLibraryW(wide.as_ptr()) }.is_null()
        })
    }
    #[cfg(not(feature = "winfsp"))]
    {
        false
    }
}
