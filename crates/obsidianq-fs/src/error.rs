use thiserror::Error;

#[derive(Debug, Error)]
pub enum FsError {
    #[error("WinFSP not installed — download from https://github.com/winfsp/winfsp/releases")]
    WinFspNotInstalled,

    #[error("WinFSP error: NTSTATUS {0:#010x}")]
    WinFsp(u32),

    /// FspFileSystemCreate returned STATUS_NO_SUCH_DEVICE — the WinFSP kernel
    /// driver device is not present. This usually means WinFSP was installed
    /// but Windows has not yet loaded the driver (a reboot is required).
    #[error(
        "WinFSP driver is not loaded (STATUS_NO_SUCH_DEVICE).\n\
         Please restart Windows to complete the WinFSP installation, then retry."
    )]
    WinFspDriverNotRunning,

    #[error("drive letter '{0}' is already in use")]
    DriveInUse(char),

    #[error("invalid drive letter '{0}' — use A-Z")]
    InvalidDriveLetter(String),

    #[error("no mount found for drive '{0}:'")]
    NotMounted(char),

    #[error("container error: {0}")]
    Container(#[from] obsidianq_core::ObsidianError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, FsError>;
