// build.rs for obsidianq-cli
//
// When built with --features winfsp the final binary links against
// winfsp-x64.lib (the WinFSP import library), which by default adds
// winfsp-x64.dll to the PE import table as a *hard* dependency.
// Windows refuses to start the process if that DLL is not found —
// even when the user only wants to encrypt or decrypt a file.
//
// The fix: instruct the MSVC linker to *delay-load* the DLL so it is
// only resolved on the first actual call into WinFSP code (i.e. when
// the user explicitly uses the mount command).
//
// delayimp.lib is part of the Windows SDK / MSVC toolchain and is
// always available when cross-compiling for win-x64.

fn main() {
    if std::env::var("CARGO_FEATURE_WINFSP").is_ok() {
        println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
}
