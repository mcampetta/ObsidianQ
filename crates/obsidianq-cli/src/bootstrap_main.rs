#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("obsidianq-bootstrapper is only supported on Windows.");
}

#[cfg(windows)]
mod win_app {
    use std::ffi::c_void;
    use std::fs::{self, File};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
    use windows_sys::Win32::Graphics::Gdi::{
        CreateSolidBrush, DeleteObject, DrawTextW, FillRect, FrameRect, GetStockObject, SetBkColor, SetBkMode,
        SetTextColor, DEFAULT_GUI_FONT, DT_CENTER, DT_SINGLELINE, DT_VCENTER, HBRUSH, TRANSPARENT,
    };
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Com::{CoTaskMemFree, CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};
    use windows_sys::Win32::UI::Controls::{DRAWITEMSTRUCT, ODS_HOTLIGHT, ODS_SELECTED};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetFocus, SetFocus};
    use windows_sys::Win32::UI::Shell::{
        SHBrowseForFolderW, SHGetPathFromIDListW, BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS, BROWSEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, GetMessageW,
        GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, MessageBoxW, RegisterClassW,
        SendMessageW, SetWindowLongPtrW, TranslateMessage, CREATESTRUCTW, CW_USEDEFAULT, ES_AUTOHSCROLL,
        ES_PASSWORD, GWLP_USERDATA, HMENU,
        ICON_BIG, ICON_SMALL, IDC_ARROW, IDCANCEL, IDNO, IDOK, IDYES, IMAGE_ICON, LR_DEFAULTSIZE,
        MB_DEFBUTTON2, MB_ICONERROR, MB_ICONQUESTION, MB_OK, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, MB_YESNOCANCEL, MSG, WM_CLOSE, WM_COMMAND,
        WM_CREATE, WM_CTLCOLORBTN, WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_DRAWITEM, WM_ERASEBKGND,
        WM_NCCREATE, WM_NCDESTROY, WM_SETFONT, WM_SETICON, WNDCLASSW, WS_CAPTION, WS_CHILD, WS_OVERLAPPED,
        WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, BS_NOTIFY, BS_OWNERDRAW, LoadCursorW, LoadImageW,
    };

    const MAGIC: &[u8; 8] = b"OBSQSFX1";
    const TRAILER_LEN: u64 = 24; // pkg_len(8) + cli_len(8) + magic(8)
    const IDC_PASSWORD: i32 = 1001;
    const IDC_MESSAGE: i32 = 1002;

    const C_BG: u32 = rgb(5, 8, 7);
    const C_TEXT: u32 = rgb(230, 237, 243);
    const C_ACCENT: u32 = rgb(0, 212, 122);
    const C_ACCENT_HOT: u32 = rgb(0, 255, 140);
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const WM_KEYDOWN_MSG: u32 = 0x0100;
    const VK_RETURN_KEY: usize = 0x0D;

    const fn rgb(r: u8, g: u8, b: u8) -> u32 {
        (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
    }

    #[derive(Debug, Clone, Copy)]
    struct SfxInfo {
        package_offset: u64,
        package_len: u64,
        cli_offset: u64,
        cli_len: u64,
    }

    pub fn start() {
        if let Err(e) = run() {
            log_failure_line(&format!("fatal: {e}"));
            show_error("ObsidianQ", &format!("Error: {e}"));
        }
    }

    fn run() -> io::Result<()> {
        let host = std::env::current_exe()?;
        if is_likely_zip_virtual_run(&host) {
            log_failure_line("blocked: attempted run from archive virtual path");
            show_error(
                "ObsidianQ",
                "Please extract all files from the ZIP first, then run Click_Here_to_Decrypt.exe.",
            );
            return Ok(());
        }
        let sfx = match read_sfx_info(&host)? {
            Some(info) => info,
            None => {
                show_error("ObsidianQ", "This file does not contain an embedded package payload.");
                return Ok(());
            }
        };

        let Some(password) = prompt_password("ObsidianQ", "Enter password to decrypt package:") else {
            return Ok(());
        };
        if password.trim().is_empty() {
            log_failure_line("validation: empty password");
            show_error("ObsidianQ", "Password is required.");
            return Ok(());
        }

        let temp_root = std::env::temp_dir().join(format!("obsq_sfx_run_{}", unique_suffix()));
        fs::create_dir_all(&temp_root)?;
        let package_zip = temp_root.join("package.zip");
        let cli_path = temp_root.join("obsidianq.exe");
        let probe_out = temp_root.join("probe_out");

        copy_range_to_file(&host, sfx.package_offset, sfx.package_len, &package_zip)?;
        copy_range_to_file(&host, sfx.cli_offset, sfx.cli_len, &cli_path)?;

        if !run_delivery_extract(&cli_path, &package_zip, &probe_out, &password)? {
            log_failure_line("extract failed: incorrect password or payload/manifest error");
            show_error("ObsidianQ", "Incorrect password or corrupted package.");
            safe_remove_dir(&temp_root);
            return Ok(());
        }
        if !contains_any_output(&probe_out)? {
            log_failure_line("extract failed: no output produced");
            show_error("ObsidianQ", "Decryption completed but no files were produced.");
            safe_remove_dir(&temp_root);
            return Ok(());
        }

        let pick = show_yes_no_cancel(
            "ObsidianQ",
            "Decrypt file/files to the same folder?",
        );
        if pick == Choice::Cancel {
            safe_remove_dir(&temp_root);
            return Ok(());
        }

        let out_dir = if pick == Choice::Yes {
            host.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(std::env::temp_dir)
        } else {
            match pick_folder("Choose where to extract files") {
                Some(path) => path,
                None => {
                    safe_remove_dir(&temp_root);
                    return Ok(());
                }
            }
        };

        fs::create_dir_all(&out_dir)?;
        move_contents_safe(&probe_out, &out_dir)?;

        if show_yes_no_default_no("ObsidianQ", "Decryption complete.\n\nRemove encrypted package now?") {
            let _ = schedule_self_delete(&host);
        }
        safe_remove_dir(&temp_root);
        Ok(())
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Choice {
        Yes,
        No,
        Cancel,
    }

    fn show_yes_no_cancel(title: &str, text: &str) -> Choice {
        let t = wide_z(title);
        let m = wide_z(text);
        let code = unsafe {
            MessageBoxW(
                std::ptr::null_mut() as HWND,
                m.as_ptr(),
                t.as_ptr(),
                MB_ICONQUESTION | MB_YESNOCANCEL | MB_SETFOREGROUND | MB_TOPMOST,
            )
        };
        match code {
            IDYES => Choice::Yes,
            IDNO => Choice::No,
            _ => Choice::Cancel,
        }
    }

    fn show_error(title: &str, text: &str) {
        let t = wide_z(title);
        let m = wide_z(text);
        unsafe {
            MessageBoxW(std::ptr::null_mut() as HWND, m.as_ptr(), t.as_ptr(), MB_ICONERROR | MB_OK | MB_SETFOREGROUND | MB_TOPMOST);
        }
    }

    fn show_yes_no_default_no(title: &str, text: &str) -> bool {
        let t = wide_z(title);
        let m = wide_z(text);
        let code = unsafe {
            MessageBoxW(
                std::ptr::null_mut() as HWND,
                m.as_ptr(),
                t.as_ptr(),
                MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST,
            )
        };
        code == IDYES
    }

    fn schedule_self_delete(path: &Path) -> io::Result<()> {
        let host = path.to_string_lossy().to_string();
        let host_ps = host.replace('\'', "''");
        let host_cmd = host.replace('"', "\"\"");

        // Path 1: hidden cmd delayed delete (reliable on most Windows systems)
        let _ = Command::new("cmd")
            .arg("/C")
            .arg(format!(
                "ping 127.0.0.1 -n 3 > nul & del /f /q \"{host_cmd}\" > nul 2>&1"
            ))
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        // Path 2: hidden PowerShell retry loop
        let ps_script = format!(
            "$p = '{host_ps}'; Start-Sleep -Milliseconds 800; \
             for ($i = 0; $i -lt 60; $i++) {{ \
               try {{ Remove-Item -LiteralPath $p -Force -ErrorAction Stop; exit 0 }} \
               catch {{ Start-Sleep -Milliseconds 500 }} \
             }}; exit 1"
        );
        let _ = Command::new("powershell")
            .arg("-NoProfile")
            .arg("-WindowStyle")
            .arg("Hidden")
            .arg("-Command")
            .arg(ps_script)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        // Path 3: fallback mark-for-delete at next reboot.
        let wide = wide_z(&host);
        unsafe {
            let _ = MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
        }
        Ok(())
    }

    fn prompt_password(caption: &str, message: &str) -> Option<String> {
        struct PasswordDialogState {
            caption: Vec<u16>,
            message: Vec<u16>,
            password: Option<String>,
            edit: HWND,
            done: bool,
            bg_brush: HBRUSH,
            border_brush: HBRUSH,
            border_hot_brush: HBRUSH,
        }

        unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
            fn get_state(hwnd: HWND) -> *mut PasswordDialogState {
                unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut PasswordDialogState }
            }

            match msg {
                WM_NCCREATE => {
                    let cs = l as *const CREATESTRUCTW;
                    if cs.is_null() {
                        return 0;
                    }
                    let state_ptr = unsafe { (*cs).lpCreateParams as *mut PasswordDialogState };
                    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize) };
                    1
                }
                WM_CREATE => {
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return 0;
                    }

                    let dark: i32 = 1;
                    let _ = unsafe { DwmSetWindowAttribute(hwnd, 20, &dark as *const _ as *const c_void, 4) };

                    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
                    let hicon = unsafe {
                        LoadImageW(
                            instance,
                            1usize as *const u16,
                            IMAGE_ICON,
                            0,
                            0,
                            LR_DEFAULTSIZE,
                        )
                    };
                    if !hicon.is_null() {
                        unsafe {
                            SendMessageW(hwnd, WM_SETICON, ICON_SMALL as usize, hicon as isize);
                            SendMessageW(hwnd, WM_SETICON, ICON_BIG as usize, hicon as isize);
                        }
                    }

                    let mut rc: RECT = unsafe { std::mem::zeroed() };
                    unsafe { GetClientRect(hwnd, &mut rc) };
                    let width = (rc.right - rc.left).max(470);

                    let class_static = wide_z("STATIC");
                    let class_edit = wide_z("EDIT");
                    let class_button = wide_z("BUTTON");
                    let txt_cancel = wide_z("CANCEL");
                    let txt_ok = wide_z("DECRYPT");

                    let _lbl = unsafe {
                        CreateWindowExW(
                            0,
                            class_static.as_ptr(),
                            (*state).message.as_ptr(),
                            WS_CHILD | WS_VISIBLE,
                            12,
                            12,
                            width - 24,
                            28,
                            hwnd,
                            IDC_MESSAGE as HMENU,
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        )
                    };

                    let edit = unsafe {
                        CreateWindowExW(
                            0,
                            class_edit.as_ptr(),
                            std::ptr::null(),
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | (ES_PASSWORD as u32) | (ES_AUTOHSCROLL as u32),
                            12,
                            46,
                            width - 24,
                            26,
                            hwnd,
                            IDC_PASSWORD as HMENU,
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        )
                    };
                    (*state).edit = edit;

                    let btn_w = (width - 27) / 2;
                    let btn_y = 90;
                    let _ = unsafe {
                        CreateWindowExW(
                            0,
                            class_button.as_ptr(),
                            txt_cancel.as_ptr(),
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_OWNERDRAW as u32) | (BS_NOTIFY as u32),
                            12,
                            btn_y,
                            btn_w,
                            30,
                            hwnd,
                            IDCANCEL as HMENU,
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        )
                    };
                    let _ = unsafe {
                        CreateWindowExW(
                            0,
                            class_button.as_ptr(),
                            txt_ok.as_ptr(),
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_OWNERDRAW as u32) | (BS_NOTIFY as u32),
                            15 + btn_w,
                            btn_y,
                            btn_w,
                            30,
                            hwnd,
                            IDOK as HMENU,
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        )
                    };

                    let hfont = unsafe { GetStockObject(DEFAULT_GUI_FONT) };
                    unsafe {
                        SendMessageW(edit, WM_SETFONT, hfont as usize, 1);
                        SetFocus(edit);
                    }
                    0
                }
                WM_COMMAND => {
                    let id = (w & 0xffff) as i32;
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return 0;
                    }
                    if id == IDOK {
                        let len = unsafe { GetWindowTextLengthW((*state).edit) };
                        if len >= 0 {
                            let mut buf = vec![0u16; len as usize + 1];
                            unsafe { GetWindowTextW((*state).edit, buf.as_mut_ptr(), buf.len() as i32) };
                            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                            (*state).password = Some(String::from_utf16_lossy(&buf[..end]));
                        }
                        unsafe { DestroyWindow(hwnd) };
                        return 0;
                    }
                    if id == IDCANCEL {
                        (*state).password = None;
                        unsafe { DestroyWindow(hwnd) };
                        return 0;
                    }
                    0
                }
                WM_DRAWITEM => {
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return 0;
                    }
                    let dis = l as *const DRAWITEMSTRUCT;
                    if dis.is_null() {
                        return 0;
                    }
                    let dis = unsafe { &*dis };
                    if dis.CtlID as i32 != IDOK && dis.CtlID as i32 != IDCANCEL {
                        return 0;
                    }

                    let is_hot = (dis.itemState & (ODS_HOTLIGHT as u32)) != 0;
                    let is_pressed = (dis.itemState & (ODS_SELECTED as u32)) != 0;
                    let border = if is_hot || is_pressed {
                        unsafe { (*state).border_hot_brush }
                    } else {
                        unsafe { (*state).border_brush }
                    };

                    unsafe {
                        FillRect(dis.hDC, &dis.rcItem, (*state).bg_brush);
                        FrameRect(dis.hDC, &dis.rcItem, border);
                        SetBkMode(dis.hDC, TRANSPARENT as i32);
                        SetTextColor(dis.hDC, C_TEXT);
                    }

                    let mut text_buf = [0u16; 32];
                    let n = unsafe { GetWindowTextW(dis.hwndItem, text_buf.as_mut_ptr(), text_buf.len() as i32) };
                    let text = if n > 0 {
                        &text_buf[..n as usize]
                    } else {
                        &[]
                    };
                    let mut rc = dis.rcItem;
                    unsafe {
                        DrawTextW(
                            dis.hDC,
                            text.as_ptr(),
                            text.len() as i32,
                            &mut rc,
                            DT_SINGLELINE | DT_CENTER | DT_VCENTER,
                        );
                    }
                    1
                }
                WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORBTN => {
                    let state = get_state(hwnd);
                    if !state.is_null() {
                        unsafe {
                            SetBkColor(w as _, C_BG);
                            SetTextColor(w as _, if msg == WM_CTLCOLOREDIT { C_ACCENT } else { C_TEXT });
                            return (*state).bg_brush as isize;
                        }
                    }
                    unsafe { DefWindowProcW(hwnd, msg, w, l) }
                }
                WM_CLOSE => {
                    let state = get_state(hwnd);
                    if !state.is_null() {
                        unsafe { (*state).password = None };
                    }
                    unsafe { DestroyWindow(hwnd) };
                    0
                }
                WM_NCDESTROY => {
                    let state = get_state(hwnd);
                    if !state.is_null() {
                        unsafe {
                            if !(*state).bg_brush.is_null() {
                                let _ = DeleteObject((*state).bg_brush as _);
                                (*state).bg_brush = std::ptr::null_mut();
                            }
                            if !(*state).border_brush.is_null() {
                                let _ = DeleteObject((*state).border_brush as _);
                                (*state).border_brush = std::ptr::null_mut();
                            }
                            if !(*state).border_hot_brush.is_null() {
                                let _ = DeleteObject((*state).border_hot_brush as _);
                                (*state).border_hot_brush = std::ptr::null_mut();
                            }
                            (*state).done = true;
                        }
                    }
                    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
                    0
                }
                WM_ERASEBKGND => {
                    let state = get_state(hwnd);
                    if !state.is_null() {
                        let mut rc: RECT = unsafe { std::mem::zeroed() };
                        unsafe {
                            GetClientRect(hwnd, &mut rc);
                            FillRect(w as _, &rc, (*state).bg_brush);
                            let edit_rc = RECT {
                                left: 11,
                                top: 45,
                                right: rc.right - 11,
                                bottom: 73,
                            };
                            FrameRect(w as _, &edit_rc, (*state).border_brush);
                        }
                        return 1;
                    }
                    unsafe { DefWindowProcW(hwnd, msg, w, l) }
                }
                _ => unsafe { DefWindowProcW(hwnd, msg, w, l) },
            }
        }

        let class_name = wide_z("ObsidianQ.PasswordDialog");
        let instance: HINSTANCE = unsafe { GetModuleHandleW(std::ptr::null()) };
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: unsafe {
                LoadImageW(
                    instance,
                    1usize as *const u16,
                    IMAGE_ICON,
                    0,
                    0,
                    LR_DEFAULTSIZE,
                ) as _
            },
            hCursor: unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) },
            lpszClassName: class_name.as_ptr(),
            lpszMenuName: std::ptr::null(),
            hbrBackground: std::ptr::null_mut(),
        };
        unsafe {
            let _ = RegisterClassW(&wc);
        }

        let state = Box::new(PasswordDialogState {
            caption: wide_z(caption),
            message: wide_z(message),
            password: None,
            edit: std::ptr::null_mut(),
            done: false,
            bg_brush: unsafe { CreateSolidBrush(C_BG) },
            border_brush: unsafe { CreateSolidBrush(C_ACCENT) },
            border_hot_brush: unsafe { CreateSolidBrush(C_ACCENT_HOT) },
        });
        let state_ptr = Box::into_raw(state);

        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class_name.as_ptr(),
                (*state_ptr).caption.as_ptr(),
                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                500,
                170,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                state_ptr as *const c_void,
            )
        };

        if hwnd.is_null() {
            unsafe {
                let _ = Box::from_raw(state_ptr);
            }
            show_error("ObsidianQ", "Unable to display password prompt.");
            return None;
        }

        let mut msg: MSG = unsafe { std::mem::zeroed() };
        loop {
            let ok = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
            if ok <= 0 {
                break;
            }
            if msg.message == WM_KEYDOWN_MSG && msg.wParam == VK_RETURN_KEY {
                let focused = unsafe { GetFocus() };
                if !focused.is_null() && unsafe { !state_ptr.is_null() && focused == (*state_ptr).edit } {
                    unsafe { SendMessageW(hwnd, WM_COMMAND, IDOK as usize, 0); }
                    if unsafe { !state_ptr.is_null() && (*state_ptr).done } {
                        break;
                    }
                    continue;
                }
            }
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            if unsafe { (*state_ptr).done } {
                break;
            }
        }

        let boxed = unsafe { Box::from_raw(state_ptr) };
        boxed.password
    }

    fn pick_folder(title: &str) -> Option<PathBuf> {
        let _ = unsafe { CoInitializeEx(std::ptr::null_mut(), COINIT_APARTMENTTHREADED as u32) };
        let title_w = wide_z(title);
        let mut display_name = [0u16; 260];
        let bi = BROWSEINFOW {
            hwndOwner: std::ptr::null_mut(),
            pidlRoot: std::ptr::null_mut(),
            pszDisplayName: display_name.as_mut_ptr(),
            lpszTitle: title_w.as_ptr(),
            ulFlags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE,
            lpfn: None,
            lParam: 0,
            iImage: 0,
        };

        let pidl = unsafe { SHBrowseForFolderW(&bi) };
        if pidl.is_null() {
            unsafe { CoUninitialize() };
            return None;
        }

        let mut path_buf = [0u16; 260];
        let ok = unsafe { SHGetPathFromIDListW(pidl, path_buf.as_mut_ptr()) } != 0;
        unsafe {
            CoTaskMemFree(pidl as _);
            CoUninitialize();
        }

        if !ok {
            return None;
        }
        let len = path_buf.iter().position(|&c| c == 0).unwrap_or(path_buf.len());
        let path = String::from_utf16_lossy(&path_buf[..len]);
        if path.is_empty() {
            None
        } else {
            Some(PathBuf::from(path))
        }
    }

    fn wide_z(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn read_sfx_info(host: &Path) -> io::Result<Option<SfxInfo>> {
        let mut f = File::open(host)?;
        let len = f.metadata()?.len();
        if len <= TRAILER_LEN {
            return Ok(None);
        }
        f.seek(SeekFrom::End(-(TRAILER_LEN as i64)))?;
        let mut trailer = [0u8; TRAILER_LEN as usize];
        f.read_exact(&mut trailer)?;
        if &trailer[16..24] != MAGIC {
            return Ok(None);
        }

        let package_len = u64::from_le_bytes(trailer[0..8].try_into().unwrap());
        let cli_len = u64::from_le_bytes(trailer[8..16].try_into().unwrap());
        if package_len == 0 || cli_len == 0 {
            return Ok(None);
        }

        let payload_start = len
            .checked_sub(TRAILER_LEN)
            .and_then(|v| v.checked_sub(package_len))
            .and_then(|v| v.checked_sub(cli_len));
        let Some(package_offset) = payload_start else {
            return Ok(None);
        };
        let cli_offset = package_offset + package_len;
        if cli_offset + cli_len > len {
            return Ok(None);
        }

        Ok(Some(SfxInfo {
            package_offset,
            package_len,
            cli_offset,
            cli_len,
        }))
    }

    fn copy_range_to_file(src_path: &Path, offset: u64, length: u64, dst_path: &Path) -> io::Result<()> {
        let mut src = File::open(src_path)?;
        let mut dst = File::create(dst_path)?;
        src.seek(SeekFrom::Start(offset))?;

        let mut remaining = length;
        let mut buf = vec![0u8; 128 * 1024];
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = src.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of embedded payload",
                ));
            }
            dst.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        dst.flush()?;
        Ok(())
    }

    fn run_delivery_extract(cli_path: &Path, package_zip: &Path, out_dir: &Path, password: &str) -> io::Result<bool> {
        let mut cmd = Command::new(cli_path);
        cmd.arg("delivery")
            .arg("extract")
            .arg(package_zip)
            .arg("--out")
            .arg(out_dir)
            .arg("--password-stdin")
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = cmd.spawn()?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(password.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
        let status = child.wait()?;
        Ok(status.success())
    }

    fn move_contents_safe(src_dir: &Path, dst_dir: &Path) -> io::Result<()> {
        if !src_dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("extracted source not found: {}", src_dir.display()),
            ));
        }
        for entry in fs::read_dir(src_dir)? {
            let entry = entry?;
            let from = entry.path();
            let name = entry.file_name();
            let to = unique_destination(dst_dir.join(name), from.is_dir());
            if from.is_dir() {
                copy_dir_recursive(&from, &to)?;
            } else {
                fs::copy(&from, &to)?;
            }
        }
        Ok(())
    }

    fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let from = entry.path();
            let to = dst.join(entry.file_name());
            if from.is_dir() {
                copy_dir_recursive(&from, &to)?;
            } else {
                let final_to = unique_destination(to, false);
                fs::copy(&from, final_to)?;
            }
        }
        Ok(())
    }

    fn unique_destination(path: PathBuf, is_dir: bool) -> PathBuf {
        if !path.exists() {
            return path;
        }
        let parent = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "output".to_string());
        let ext = path.extension().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();

        for i in 1..10_000 {
            let candidate_name = if is_dir {
                format!("{stem} ({i})")
            } else if ext.is_empty() {
                format!("{stem} ({i})")
            } else {
                format!("{stem} ({i}).{ext}")
            };
            let candidate = parent.join(candidate_name);
            if !candidate.exists() {
                return candidate;
            }
        }
        path
    }

    fn unique_suffix() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("{now}_{}", std::process::id())
    }

    fn safe_remove_dir(path: &Path) {
        let _ = fs::remove_dir_all(path);
    }

    fn contains_any_output(path: &Path) -> io::Result<bool> {
        if !path.is_dir() {
            return Ok(false);
        }
        let mut it = fs::read_dir(path)?;
        Ok(it.next().is_some())
    }

    fn is_likely_zip_virtual_run(host: &Path) -> bool {
        let full = host.to_string_lossy().replace('/', "\\").to_lowercase();
        let file_name = host
            .file_name()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if full.contains(".zip\\") || full.contains(".rar\\") || full.contains(".7z\\") {
            return true;
        }
        // Explorer may execute directly from an archive-backed temp location without a ".zip\" segment.
        // Guard package entrypoints launched from temp to avoid "successful" extraction into transient folders.
        let temp = std::env::temp_dir().to_string_lossy().replace('/', "\\").to_lowercase();
        if full.starts_with(&temp)
            && (file_name.starts_with("click_here_to_decrypt")
                || file_name.ends_with("_securedelivery.exe"))
        {
            return true;
        }
        full.contains("\\appdata\\local\\temp\\temporary internet files\\")
            || full.contains("\\appdata\\local\\temp\\temporary internet files (")
            || full.contains("\\appdata\\local\\temp\\zip")
            || full.contains("\\appdata\\local\\temp\\7z")
            || full.contains("\\appdata\\local\\temp\\rar$")
            || full.contains("\\appdata\\local\\temp\\temp")
    }

    fn log_failure_line(message: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!("{now} | {message}\n");
        let log = std::env::temp_dir().join("obsq_bootstrap.log");
        let _ = fs::OpenOptions::new().create(true).append(true).open(log).and_then(|mut f| f.write_all(line.as_bytes()));
    }
}

#[cfg(windows)]
fn main() {
    win_app::start();
}
