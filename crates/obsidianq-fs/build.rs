// build.rs for obsidianq-fs
//
// When the "winfsp" feature is enabled, locates the WinFSP SDK installation
// and wires up the linker search path + import library.
//
// WinFSP default install: C:\Program Files (x86)\WinFsp
// Import library      : <sdk>\lib\winfsp-x64.lib
//
// If WinFSP SDK is not found, the build fails with a clear error pointing
// to the download page.

fn main() {
    #[cfg(feature = "winfsp")]
    {
        // Only attempt link setup on Windows.
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
            panic!("obsidianq-fs: WinFSP mount is only supported on Windows");
        }

        let sdk = find_winfsp_sdk().unwrap_or_else(|| {
            panic!(
                "obsidianq-fs: WinFSP SDK not found.\n\
                 Download the WinFSP installer from:\n\
                 https://github.com/winfsp/winfsp/releases\n\
                 Install the SDK component, then rebuild.\n\
                 Alternatively, build without --features winfsp to get stubs."
            )
        });

        println!("cargo:rustc-link-search={}", sdk.display());
        println!("cargo:rustc-link-lib=winfsp-x64");
        println!("cargo:rerun-if-env-changed=WINFSP_SDK");
    }
}

#[cfg(feature = "winfsp")]
fn find_winfsp_sdk() -> Option<std::path::PathBuf> {
    // 1. Allow override via environment variable.
    if let Ok(p) = std::env::var("WINFSP_SDK") {
        let lib = std::path::PathBuf::from(&p).join("lib");
        if lib.join("winfsp-x64.lib").exists() {
            return Some(lib);
        }
    }

    // 2. Standard installation locations.
    let candidates = [
        r"C:\Program Files (x86)\WinFsp\lib",
        r"C:\Program Files\WinFsp\lib",
    ];
    for c in &candidates {
        let lib = std::path::Path::new(c);
        if lib.join("winfsp-x64.lib").exists() {
            return Some(lib.to_owned());
        }
    }

    None
}
