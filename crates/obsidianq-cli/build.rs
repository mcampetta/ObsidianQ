#[cfg(windows)]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("../../assets/icon/obsidianq_icon_v2.ico");
    res.set_manifest_file("app.manifest");
    if let Err(e) = res.compile() {
        panic!("failed to compile Windows resources: {e}");
    }
}

#[cfg(not(windows))]
fn main() {}
