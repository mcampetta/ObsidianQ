#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("obsidianq-bootstrapper is only supported on Windows.");
}

#[cfg(windows)]
mod win_app {
    use serde_json::Value;
    use std::ffi::c_void;
    use std::fs::{self, File};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
    use windows_sys::Win32::Graphics::Gdi::{
        BeginPaint, CreateFontW, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint, FillRect,
        FrameRect, GetStockObject, InvalidateRect, SelectObject, SetBkColor, SetBkMode,
        SetTextColor, DEFAULT_GUI_FONT, DT_CENTER, DT_LEFT, DT_SINGLELINE, DT_VCENTER, HBRUSH,
        PAINTSTRUCT, TRANSPARENT,
    };
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_APARTMENTTHREADED,
    };
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE, GMEM_ZEROINIT,
    };
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
    use windows_sys::Win32::UI::Controls::{DRAWITEMSTRUCT, ODS_HOTLIGHT, ODS_SELECTED};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        EnableWindow, GetFocus, ReleaseCapture, SetCapture, SetFocus,
    };
    use windows_sys::Win32::UI::Shell::{
        SHBrowseForFolderW, SHGetPathFromIDListW, BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS,
        BROWSEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
        GetMessageW, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, LoadCursorW,
        LoadImageW, RegisterClassW, SendMessageW, SetWindowLongPtrW, TranslateMessage, BS_NOTIFY,
        BS_OWNERDRAW, CREATESTRUCTW, CW_USEDEFAULT, ES_AUTOHSCROLL, ES_PASSWORD, GWLP_USERDATA,
        HMENU, ICON_BIG, ICON_SMALL, IDCANCEL, IDC_ARROW, IDNO, IDOK, IDYES, IMAGE_ICON,
        LR_DEFAULTSIZE, MSG, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_CTLCOLORBTN, WM_CTLCOLOREDIT,
        WM_CTLCOLORSTATIC, WM_DRAWITEM, WM_ERASEBKGND, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE,
        WM_MOUSEWHEEL, WM_NCCREATE, WM_NCDESTROY, WM_PAINT, WM_SETFONT, WM_SETICON, WNDCLASSW,
        WS_CAPTION, WS_CHILD, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
    };

    const MAGIC: &[u8; 8] = b"OBSQSFX1";
    const TRAILER_LEN: u64 = 24; // pkg_len(8) + cli_len(8) + magic(8)
    const IDC_PASSWORD: i32 = 1001;
    const IDC_MESSAGE: i32 = 1002;
    const IDC_INFO: i32 = 1003;
    const IDC_COPY: i32 = 1004;

    const C_BG: u32 = rgb(5, 8, 7);
    const C_TEXT: u32 = rgb(230, 237, 243);
    const C_ACCENT: u32 = rgb(0, 212, 122);
    const C_ACCENT_HOT: u32 = rgb(0, 255, 140);
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const WM_KEYDOWN_MSG: u32 = 0x0100;
    const VK_RETURN_KEY: usize = 0x0D;
    const SUMMARY_LINE_HEIGHT: i32 = 22;
    const SUMMARY_SCROLLBAR_MIN_THUMB: i32 = 28;

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

    struct PackageSummary {
        package_id: String,
        sender: String,
        created: String,
        app_version: String,
        recipient_mode: String,
        files: Vec<String>,
        signed: bool,
        sender_identity_present: bool,
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
                show_error(
                    "ObsidianQ",
                    "This file does not contain an embedded package payload.",
                );
                return Ok(());
            }
        };

        let temp_root = std::env::temp_dir().join(format!("obsq_sfx_run_{}", unique_suffix()));
        fs::create_dir_all(&temp_root)?;
        let package_zip = temp_root.join("package.zip");
        let cli_path = temp_root.join("obsidianq.exe");
        let probe_out = temp_root.join("probe_out");

        copy_range_to_file(&host, sfx.package_offset, sfx.package_len, &package_zip)?;
        copy_range_to_file(&host, sfx.cli_offset, sfx.cli_len, &cli_path)?;

        let summary = match inspect_package_summary(&cli_path, &package_zip) {
            Ok(v) => v,
            Err(e) => {
                log_failure_line(&format!("inspect failed: {e}"));
                show_error("ObsidianQ", &format!("Unable to inspect package: {e}"));
                safe_remove_dir(&temp_root);
                return Ok(());
            }
        };
        let Some(password) = prompt_password(
            "ObsidianQ",
            "Enter password to decrypt package:",
            Some(&summary),
        ) else {
            safe_remove_dir(&temp_root);
            return Ok(());
        };
        if password.trim().is_empty() {
            log_failure_line("validation: empty password");
            show_error("ObsidianQ", "Password is required.");
            safe_remove_dir(&temp_root);
            return Ok(());
        }

        if !run_delivery_extract(&cli_path, &package_zip, &probe_out, &password)? {
            log_failure_line("extract failed: incorrect password or payload/manifest error");
            show_error("ObsidianQ", "Incorrect password or corrupted package.");
            safe_remove_dir(&temp_root);
            return Ok(());
        }
        if !contains_any_output(&probe_out)? {
            log_failure_line("extract failed: no output produced");
            show_error(
                "ObsidianQ",
                "Decryption completed but no files were produced.",
            );
            safe_remove_dir(&temp_root);
            return Ok(());
        }

        let pick = show_yes_no_cancel("ObsidianQ", "Decrypt file/files to the same folder?");

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
        safe_remove_dir(&temp_root);
        Ok(())
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Choice {
        Yes,
        No,
    }

    fn show_themed_dialog(
        title: &str,
        text: &str,
        buttons: &[(i32, &str)],
        default_id: i32,
        close_result: i32,
    ) -> i32 {
        struct DialogState {
            caption: Vec<u16>,
            message: Vec<u16>,
            buttons: Vec<(i32, Vec<u16>)>,
            close_result: i32,
            result: i32,
            done: bool,
            bg_brush: HBRUSH,
            border_brush: HBRUSH,
            border_hot_brush: HBRUSH,
        }

        unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
            fn get_state(hwnd: HWND) -> *mut DialogState {
                unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut DialogState }
            }

            match msg {
                WM_NCCREATE => {
                    let cs = l as *const CREATESTRUCTW;
                    if cs.is_null() {
                        return 0;
                    }
                    let state_ptr = unsafe { (*cs).lpCreateParams as *mut DialogState };
                    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize) };
                    1
                }
                WM_CREATE => {
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return 0;
                    }

                    let dark: i32 = 1;
                    let _ = unsafe {
                        DwmSetWindowAttribute(hwnd, 20, &dark as *const _ as *const c_void, 4)
                    };

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
                    let class_button = wide_z("BUTTON");

                    let _ = unsafe {
                        CreateWindowExW(
                            0,
                            class_static.as_ptr(),
                            (*state).message.as_ptr(),
                            WS_CHILD | WS_VISIBLE,
                            16,
                            16,
                            width - 32,
                            44,
                            hwnd,
                            IDC_MESSAGE as HMENU,
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        )
                    };

                    let button_count = unsafe { (*state).buttons.len() as i32 };
                    let gap = 6;
                    let total_gap = gap * (button_count - 1).max(0);
                    let btn_w = ((width - 32 - total_gap) / button_count.max(1)).max(90);
                    let btn_y = 50;
                    let mut x = 16;
                    for (id, label_w) in unsafe { &(*state).buttons } {
                        let _btn = unsafe {
                            CreateWindowExW(
                                0,
                                class_button.as_ptr(),
                                label_w.as_ptr(),
                                WS_CHILD
                                    | WS_VISIBLE
                                    | WS_TABSTOP
                                    | (BS_OWNERDRAW as u32)
                                    | (BS_NOTIFY as u32),
                                x,
                                btn_y,
                                btn_w,
                                30,
                                hwnd,
                                *id as HMENU,
                                std::ptr::null_mut(),
                                std::ptr::null(),
                            )
                        };
                        x += btn_w + gap;
                    }
                    0
                }
                WM_COMMAND => {
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return 0;
                    }
                    let id = (w & 0xffff) as i32;
                    if unsafe {
                        (&(*state).buttons)
                            .iter()
                            .any(|(button_id, _)| *button_id == id)
                    } {
                        unsafe {
                            (*state).result = id;
                            DestroyWindow(hwnd);
                        }
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
                    let n = unsafe {
                        GetWindowTextW(dis.hwndItem, text_buf.as_mut_ptr(), text_buf.len() as i32)
                    };
                    let text = if n > 0 { &text_buf[..n as usize] } else { &[] };
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
                WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
                    let state = get_state(hwnd);
                    if !state.is_null() {
                        unsafe {
                            SetBkColor(w as _, C_BG);
                            SetTextColor(w as _, C_TEXT);
                            return (*state).bg_brush as isize;
                        }
                    }
                    unsafe { DefWindowProcW(hwnd, msg, w, l) }
                }
                WM_CLOSE => {
                    let state = get_state(hwnd);
                    if !state.is_null() {
                        unsafe { (*state).result = (*state).close_result };
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
                            }
                            if !(*state).border_brush.is_null() {
                                let _ = DeleteObject((*state).border_brush as _);
                            }
                            if !(*state).border_hot_brush.is_null() {
                                let _ = DeleteObject((*state).border_hot_brush as _);
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
                        }
                        return 1;
                    }
                    unsafe { DefWindowProcW(hwnd, msg, w, l) }
                }
                _ => unsafe { DefWindowProcW(hwnd, msg, w, l) },
            }
        }

        let class_name = wide_z("ObsidianQ.ThemedDialog");
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

        let state = Box::new(DialogState {
            caption: wide_z(title),
            message: wide_z(text),
            buttons: buttons
                .iter()
                .map(|(id, label)| (*id, wide_z(label)))
                .collect(),
            close_result,
            result: default_id,
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
                132,
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
            return close_result;
        }

        let mut msg: MSG = unsafe { std::mem::zeroed() };
        loop {
            let ok = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
            if ok <= 0 {
                break;
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
        boxed.result
    }

    fn show_yes_no_cancel(title: &str, text: &str) -> Choice {
        let code = show_themed_dialog(title, text, &[(IDYES, "YES"), (IDNO, "NO")], IDYES, IDNO);
        match code {
            IDYES => Choice::Yes,
            _ => Choice::No,
        }
    }

    fn show_error(title: &str, text: &str) {
        let _ = show_themed_dialog(title, text, &[(IDOK, "OK")], IDOK, IDOK);
    }

    fn prompt_password(
        caption: &str,
        message: &str,
        summary: Option<&PackageSummary>,
    ) -> Option<String> {
        struct PasswordDialogState {
            caption: Vec<u16>,
            message: Vec<u16>,
            has_summary: bool,
            summary: Vec<u16>,
            password: Option<String>,
            edit: HWND,
            decrypt_button: HWND,
            edit_font: HBRUSH,
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
                    let _ = unsafe {
                        DwmSetWindowAttribute(hwnd, 20, &dark as *const _ as *const c_void, 4)
                    };

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
                    let has_summary = unsafe { (*state).has_summary };

                    let class_static = wide_z("STATIC");
                    let class_edit = wide_z("EDIT");
                    let class_button = wide_z("BUTTON");
                    let txt_cancel = wide_z("CANCEL");
                    let txt_info = wide_z("INFO");
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
                            WS_CHILD
                                | WS_VISIBLE
                                | WS_TABSTOP
                                | (ES_PASSWORD as u32)
                                | (ES_AUTOHSCROLL as u32),
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

                    let btn_y = 90;
                    if has_summary {
                        let btn_w = (width - 36) / 3;
                        let decrypt_button = unsafe {
                            CreateWindowExW(
                                0,
                                class_button.as_ptr(),
                                txt_cancel.as_ptr(),
                                WS_CHILD
                                    | WS_VISIBLE
                                    | WS_TABSTOP
                                    | (BS_OWNERDRAW as u32)
                                    | (BS_NOTIFY as u32),
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
                                txt_info.as_ptr(),
                                WS_CHILD
                                    | WS_VISIBLE
                                    | WS_TABSTOP
                                    | (BS_OWNERDRAW as u32)
                                    | (BS_NOTIFY as u32),
                                18 + btn_w,
                                btn_y,
                                btn_w,
                                30,
                                hwnd,
                                IDC_INFO as HMENU,
                                std::ptr::null_mut(),
                                std::ptr::null(),
                            )
                        };
                        let _ = unsafe {
                            CreateWindowExW(
                                0,
                                class_button.as_ptr(),
                                txt_ok.as_ptr(),
                                WS_CHILD
                                    | WS_VISIBLE
                                    | WS_TABSTOP
                                    | (BS_OWNERDRAW as u32)
                                    | (BS_NOTIFY as u32),
                                24 + (btn_w * 2),
                                btn_y,
                                btn_w,
                                30,
                                hwnd,
                                IDOK as HMENU,
                                std::ptr::null_mut(),
                                std::ptr::null(),
                            )
                        };
                        (*state).decrypt_button = decrypt_button;
                    } else {
                        let btn_w = (width - 27) / 2;
                        let decrypt_button = unsafe {
                            CreateWindowExW(
                                0,
                                class_button.as_ptr(),
                                txt_cancel.as_ptr(),
                                WS_CHILD
                                    | WS_VISIBLE
                                    | WS_TABSTOP
                                    | (BS_OWNERDRAW as u32)
                                    | (BS_NOTIFY as u32),
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
                                WS_CHILD
                                    | WS_VISIBLE
                                    | WS_TABSTOP
                                    | (BS_OWNERDRAW as u32)
                                    | (BS_NOTIFY as u32),
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
                        (*state).decrypt_button = decrypt_button;
                    }

                    let hfont = unsafe {
                        CreateFontW(
                            -22,
                            0,
                            0,
                            0,
                            400,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            wide_z("Consolas").as_ptr(),
                        )
                    };
                    (*state).edit_font = if hfont.is_null() {
                        GetStockObject(DEFAULT_GUI_FONT)
                    } else {
                        hfont as _
                    };
                    unsafe {
                        SendMessageW(edit, WM_SETFONT, (*state).edit_font as usize, 1);
                        SetFocus(edit);
                    }
                    0
                }
                WM_COMMAND => {
                    let id = (w & 0xffff) as i32;
                    let notify = ((w >> 16) & 0xffff) as u16;
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return 0;
                    }
                    if id == IDOK && notify == 0 {
                        let len = unsafe { GetWindowTextLengthW((*state).edit) };
                        if len >= 0 {
                            let mut buf = vec![0u16; len as usize + 1];
                            unsafe {
                                GetWindowTextW((*state).edit, buf.as_mut_ptr(), buf.len() as i32)
                            };
                            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                            (*state).password = Some(String::from_utf16_lossy(&buf[..end]));
                        }
                        unsafe { DestroyWindow(hwnd) };
                        return 0;
                    }
                    if id == IDCANCEL && notify == 0 {
                        (*state).password = None;
                        unsafe { DestroyWindow(hwnd) };
                        return 0;
                    }
                    if id == IDC_INFO && notify == 0 {
                        let summary = utf16z_to_string(&(*state).summary);
                        if !summary.trim().is_empty() {
                            if !(*state).decrypt_button.is_null() {
                                unsafe {
                                    EnableWindow((*state).decrypt_button, 0);
                                }
                            }
                            show_summary_dialog("ObsidianQ", "Package Information", &summary);
                            if !(*state).decrypt_button.is_null() {
                                unsafe {
                                    EnableWindow((*state).decrypt_button, 1);
                                }
                            }
                        }
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
                    if dis.CtlID as i32 != IDOK
                        && dis.CtlID as i32 != IDCANCEL
                        && dis.CtlID as i32 != IDC_INFO
                    {
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
                    let n = unsafe {
                        GetWindowTextW(dis.hwndItem, text_buf.as_mut_ptr(), text_buf.len() as i32)
                    };
                    let text = if n > 0 { &text_buf[..n as usize] } else { &[] };
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
                            SetTextColor(
                                w as _,
                                if msg == WM_CTLCOLOREDIT {
                                    C_ACCENT
                                } else {
                                    C_TEXT
                                },
                            );
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
                            if !(*state).edit_font.is_null()
                                && (*state).edit_font != GetStockObject(DEFAULT_GUI_FONT) as _
                            {
                                let _ = DeleteObject((*state).edit_font as _);
                                (*state).edit_font = std::ptr::null_mut();
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
            has_summary: summary.is_some(),
            summary: wide_z(&summary_text(summary)),
            password: None,
            edit: std::ptr::null_mut(),
            decrypt_button: std::ptr::null_mut(),
            edit_font: std::ptr::null_mut(),
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
                if !focused.is_null()
                    && unsafe { !state_ptr.is_null() && focused == (*state_ptr).edit }
                {
                    unsafe {
                        SendMessageW(hwnd, WM_COMMAND, IDOK as usize, 0);
                    }
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

    fn summary_text(summary: Option<&PackageSummary>) -> String {
        fn mark(ok: bool) -> &'static str {
            if ok {
                "✓"
            } else {
                "X"
            }
        }

        let Some(summary) = summary else {
            return String::new();
        };
        let mut msg = String::new();
        msg.push_str("Secure Delivery Package\n\n");
        msg.push_str(&format!("Package ID: {}\n", summary.package_id));
        msg.push_str(&format!("Signing identity: {}\n", summary.sender));
        msg.push_str(&format!("Created: {}\n", summary.created));
        msg.push_str(&format!("Created by version: {}\n", summary.app_version));
        msg.push_str(&format!("Recipient mode: {}\n", summary.recipient_mode));
        msg.push('\n');
        msg.push_str("Files:\n");
        if summary.files.is_empty() {
            msg.push_str("- (not listed)\n");
        } else {
            for file in summary.files.iter().take(12) {
                msg.push_str(&format!("- {file}\n"));
            }
            if summary.files.len() > 12 {
                msg.push_str(&format!("- ... and {} more\n", summary.files.len() - 12));
            }
        }
        msg.push_str("\nVerification:\n");
        msg.push_str(&format!(
            "{} {}\n",
            mark(summary.signed),
            if summary.signed {
                "Package signature valid"
            } else {
                "Package is not signed"
            }
        ));
        msg.push_str(&format!(
            "{} {}\n",
            mark(summary.sender_identity_present),
            if summary.sender_identity_present {
                "Signing identity present"
            } else {
                "Signing identity missing"
            }
        ));
        msg.push_str(&format!("{} Contents match manifest\n", mark(true)));
        msg.push_str(&format!("{} No tampering detected", mark(true)));
        msg.replace('\n', "\r\n")
    }

    fn utf16z_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    fn split_summary_lines(summary: &str) -> Vec<Vec<u16>> {
        summary
            .replace("\r\n", "\n")
            .split('\n')
            .map(|line| line.encode_utf16().collect::<Vec<u16>>())
            .collect()
    }

    fn summary_panel_rect(client: &RECT) -> RECT {
        RECT {
            left: 18,
            top: 46,
            right: client.right - 18,
            bottom: client.bottom - 58,
        }
    }

    fn summary_text_rect(panel: &RECT) -> RECT {
        RECT {
            left: panel.left + 12,
            top: panel.top + 10,
            right: panel.right - 26,
            bottom: panel.bottom - 10,
        }
    }

    fn summary_scrollbar_rect(panel: &RECT) -> RECT {
        RECT {
            left: panel.right - 16,
            top: panel.top + 10,
            right: panel.right - 8,
            bottom: panel.bottom - 10,
        }
    }

    fn summary_visible_line_count(text_rect: &RECT) -> i32 {
        ((text_rect.bottom - text_rect.top) / SUMMARY_LINE_HEIGHT).max(1)
    }

    fn clamp_summary_scroll(scroll: i32, total_lines: i32, visible_lines: i32) -> i32 {
        let max_scroll = (total_lines - visible_lines).max(0);
        scroll.clamp(0, max_scroll)
    }

    fn summary_thumb_rect(
        scrollbar: &RECT,
        total_lines: i32,
        visible_lines: i32,
        scroll_lines: i32,
    ) -> RECT {
        let track_height = (scrollbar.bottom - scrollbar.top).max(1);
        if total_lines <= visible_lines || total_lines <= 0 {
            return *scrollbar;
        }
        let max_scroll = (total_lines - visible_lines).max(1);
        let mut thumb_height =
            (track_height * visible_lines / total_lines).max(SUMMARY_SCROLLBAR_MIN_THUMB);
        thumb_height = thumb_height.min(track_height);
        let travel = (track_height - thumb_height).max(1);
        let thumb_top = scrollbar.top + (travel * scroll_lines / max_scroll);
        RECT {
            left: scrollbar.left,
            top: thumb_top,
            right: scrollbar.right,
            bottom: thumb_top + thumb_height,
        }
    }

    fn point_in_rect(rect: &RECT, x: i32, y: i32) -> bool {
        x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom
    }

    fn lparam_x(l: LPARAM) -> i32 {
        (l as u32 & 0xffff) as i16 as i32
    }

    fn lparam_y(l: LPARAM) -> i32 {
        ((l as u32 >> 16) & 0xffff) as i16 as i32
    }

    fn wheel_delta(w: WPARAM) -> i32 {
        ((w as u32 >> 16) & 0xffff) as i16 as i32
    }

    fn invalidate_summary_panel(hwnd: HWND) {
        let mut client: RECT = unsafe { std::mem::zeroed() };
        unsafe {
            GetClientRect(hwnd, &mut client);
            let panel = summary_panel_rect(&client);
            let _ = InvalidateRect(hwnd, &panel, 0);
        }
    }

    fn copy_text_to_clipboard(hwnd: HWND, text: &str) -> bool {
        let wide = wide_z(text);
        let bytes = wide.len() * std::mem::size_of::<u16>();
        unsafe {
            if OpenClipboard(hwnd) == 0 {
                return false;
            }
            if EmptyClipboard() == 0 {
                let _ = CloseClipboard();
                return false;
            }
            let mem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
            if mem.is_null() {
                let _ = CloseClipboard();
                return false;
            }
            let ptr = GlobalLock(mem) as *mut u16;
            if ptr.is_null() {
                let _ = CloseClipboard();
                return false;
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
            let _ = GlobalUnlock(mem);
            if SetClipboardData(CF_UNICODETEXT.into(), mem).is_null() {
                let _ = CloseClipboard();
                return false;
            }
            let _ = CloseClipboard();
        }
        true
    }

    fn show_summary_dialog(caption: &str, title: &str, summary: &str) {
        struct SummaryDialogState {
            caption: Vec<u16>,
            title: Vec<u16>,
            summary_text: Vec<u16>,
            summary_lines: Vec<Vec<u16>>,
            title_font: HBRUSH,
            body_font: HBRUSH,
            scroll_lines: i32,
            dragging_thumb: bool,
            drag_offset: i32,
            done: bool,
            bg_brush: HBRUSH,
            panel_brush: HBRUSH,
            border_brush: HBRUSH,
            border_hot_brush: HBRUSH,
        }

        unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
            fn get_state(hwnd: HWND) -> *mut SummaryDialogState {
                unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut SummaryDialogState }
            }

            match msg {
                WM_NCCREATE => {
                    let cs = l as *const CREATESTRUCTW;
                    if cs.is_null() {
                        return 0;
                    }
                    let state_ptr = unsafe { (*cs).lpCreateParams as *mut SummaryDialogState };
                    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize) };
                    1
                }
                WM_CREATE => {
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return 0;
                    }

                    let dark: i32 = 1;
                    let _ = unsafe {
                        DwmSetWindowAttribute(hwnd, 20, &dark as *const _ as *const c_void, 4)
                    };

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

                    let class_static = wide_z("STATIC");
                    let class_button = wide_z("BUTTON");
                    let txt_copy = wide_z("COPY");
                    let txt_close = wide_z("CLOSE");

                    let mut rc: RECT = unsafe { std::mem::zeroed() };
                    unsafe { GetClientRect(hwnd, &mut rc) };
                    let width = rc.right - rc.left;
                    let height = rc.bottom - rc.top;

                    let title_label = unsafe {
                        CreateWindowExW(
                            0,
                            class_static.as_ptr(),
                            (*state).title.as_ptr(),
                            WS_CHILD | WS_VISIBLE,
                            18,
                            12,
                            width - 36,
                            28,
                            hwnd,
                            3001 as HMENU,
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        )
                    };
                    let _ = unsafe {
                        CreateWindowExW(
                            0,
                            class_button.as_ptr(),
                            txt_copy.as_ptr(),
                            WS_CHILD
                                | WS_VISIBLE
                                | WS_TABSTOP
                                | (BS_OWNERDRAW as u32)
                                | (BS_NOTIFY as u32),
                            width - 224,
                            height - 40,
                            100,
                            30,
                            hwnd,
                            IDC_COPY as HMENU,
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        )
                    };
                    let _ = unsafe {
                        CreateWindowExW(
                            0,
                            class_button.as_ptr(),
                            txt_close.as_ptr(),
                            WS_CHILD
                                | WS_VISIBLE
                                | WS_TABSTOP
                                | (BS_OWNERDRAW as u32)
                                | (BS_NOTIFY as u32),
                            width - 118,
                            height - 40,
                            100,
                            30,
                            hwnd,
                            IDCANCEL as HMENU,
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        )
                    };

                    let title_font = unsafe {
                        CreateFontW(
                            -20,
                            0,
                            0,
                            0,
                            600,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            wide_z("Segoe UI").as_ptr(),
                        )
                    };
                    (*state).title_font = if title_font.is_null() {
                        GetStockObject(DEFAULT_GUI_FONT)
                    } else {
                        title_font as _
                    };

                    let body_font = unsafe {
                        CreateFontW(
                            -13,
                            0,
                            0,
                            0,
                            400,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            wide_z("Consolas").as_ptr(),
                        )
                    };
                    (*state).body_font = if body_font.is_null() {
                        GetStockObject(DEFAULT_GUI_FONT)
                    } else {
                        body_font as _
                    };
                    unsafe {
                        SendMessageW(title_label, WM_SETFONT, (*state).title_font as usize, 1);
                    }
                    invalidate_summary_panel(hwnd);
                    0
                }
                WM_COMMAND => {
                    let id = (w & 0xffff) as i32;
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return 0;
                    }
                    if id == IDC_COPY {
                        let copied =
                            copy_text_to_clipboard(hwnd, &utf16z_to_string(&(*state).summary_text));
                        if !copied {
                            show_error(
                                "ObsidianQ",
                                "Unable to copy package information to the clipboard.",
                            );
                        }
                        return 0;
                    }
                    if id == IDCANCEL || id == IDOK {
                        unsafe { DestroyWindow(hwnd) };
                        return 0;
                    }
                    0
                }
                WM_LBUTTONDOWN => {
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return 0;
                    }
                    let mut client: RECT = unsafe { std::mem::zeroed() };
                    unsafe { GetClientRect(hwnd, &mut client) };
                    let panel = summary_panel_rect(&client);
                    let scrollbar = summary_scrollbar_rect(&panel);
                    let text_rect = summary_text_rect(&panel);
                    let visible_lines = summary_visible_line_count(&text_rect);
                    let total_lines = unsafe { (*state).summary_lines.len() as i32 };
                    let thumb =
                        summary_thumb_rect(&scrollbar, total_lines, visible_lines, unsafe {
                            (*state).scroll_lines
                        });
                    let x = lparam_x(l);
                    let y = lparam_y(l);
                    if point_in_rect(&thumb, x, y) {
                        unsafe {
                            (*state).dragging_thumb = true;
                            (*state).drag_offset = y - thumb.top;
                            SetCapture(hwnd);
                        }
                        return 0;
                    }
                    if point_in_rect(&scrollbar, x, y) {
                        let next_scroll = if y < thumb.top {
                            unsafe { (*state).scroll_lines - visible_lines }
                        } else {
                            unsafe { (*state).scroll_lines + visible_lines }
                        };
                        unsafe {
                            (*state).scroll_lines =
                                clamp_summary_scroll(next_scroll, total_lines, visible_lines);
                        }
                        invalidate_summary_panel(hwnd);
                    }
                    0
                }
                WM_MOUSEMOVE => {
                    let state = get_state(hwnd);
                    if state.is_null() || unsafe { !(*state).dragging_thumb } {
                        return 0;
                    }
                    let mut client: RECT = unsafe { std::mem::zeroed() };
                    unsafe { GetClientRect(hwnd, &mut client) };
                    let panel = summary_panel_rect(&client);
                    let scrollbar = summary_scrollbar_rect(&panel);
                    let text_rect = summary_text_rect(&panel);
                    let visible_lines = summary_visible_line_count(&text_rect);
                    let total_lines = unsafe { (*state).summary_lines.len() as i32 };
                    if total_lines <= visible_lines {
                        return 0;
                    }
                    let thumb =
                        summary_thumb_rect(&scrollbar, total_lines, visible_lines, unsafe {
                            (*state).scroll_lines
                        });
                    let thumb_height = (thumb.bottom - thumb.top).max(1);
                    let travel = ((scrollbar.bottom - scrollbar.top) - thumb_height).max(1);
                    let y = lparam_y(l);
                    let new_thumb_top = (y - unsafe { (*state).drag_offset })
                        .clamp(scrollbar.top, scrollbar.bottom - thumb_height);
                    let new_scroll = ((new_thumb_top - scrollbar.top)
                        * (total_lines - visible_lines).max(1))
                        / travel;
                    unsafe {
                        (*state).scroll_lines =
                            clamp_summary_scroll(new_scroll, total_lines, visible_lines);
                    }
                    invalidate_summary_panel(hwnd);
                    0
                }
                WM_LBUTTONUP => {
                    let state = get_state(hwnd);
                    if !state.is_null() && unsafe { (*state).dragging_thumb } {
                        unsafe {
                            (*state).dragging_thumb = false;
                            ReleaseCapture();
                        }
                    }
                    0
                }
                WM_MOUSEWHEEL => {
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return 0;
                    }
                    let mut client: RECT = unsafe { std::mem::zeroed() };
                    unsafe { GetClientRect(hwnd, &mut client) };
                    let panel = summary_panel_rect(&client);
                    let text_rect = summary_text_rect(&panel);
                    let visible_lines = summary_visible_line_count(&text_rect);
                    let total_lines = unsafe { (*state).summary_lines.len() as i32 };
                    let steps = (wheel_delta(w) / 120).clamp(-8, 8);
                    if steps != 0 {
                        unsafe {
                            (*state).scroll_lines = clamp_summary_scroll(
                                (*state).scroll_lines - (steps * 3),
                                total_lines,
                                visible_lines,
                            );
                        }
                        invalidate_summary_panel(hwnd);
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
                    if dis.CtlID as i32 != IDCANCEL
                        && dis.CtlID as i32 != IDOK
                        && dis.CtlID as i32 != IDC_COPY
                    {
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
                    let n = unsafe {
                        GetWindowTextW(dis.hwndItem, text_buf.as_mut_ptr(), text_buf.len() as i32)
                    };
                    let text = if n > 0 { &text_buf[..n as usize] } else { &[] };
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
                WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
                    let state = get_state(hwnd);
                    if !state.is_null() {
                        unsafe {
                            SetBkColor(w as _, C_BG);
                            SetTextColor(
                                w as _,
                                if msg == WM_CTLCOLORBTN {
                                    C_TEXT
                                } else {
                                    C_ACCENT
                                },
                            );
                            return (*state).bg_brush as isize;
                        }
                    }
                    unsafe { DefWindowProcW(hwnd, msg, w, l) }
                }
                WM_PAINT => {
                    let state = get_state(hwnd);
                    if state.is_null() {
                        return unsafe { DefWindowProcW(hwnd, msg, w, l) };
                    }
                    let mut ps: PAINTSTRUCT = unsafe { std::mem::zeroed() };
                    let hdc = unsafe { BeginPaint(hwnd, &mut ps) };
                    let mut client: RECT = unsafe { std::mem::zeroed() };
                    unsafe { GetClientRect(hwnd, &mut client) };
                    let panel = summary_panel_rect(&client);
                    let text_rect = summary_text_rect(&panel);
                    let scrollbar = summary_scrollbar_rect(&panel);
                    let visible_lines = summary_visible_line_count(&text_rect);
                    let total_lines = unsafe { (*state).summary_lines.len() as i32 };
                    let scroll_lines = unsafe {
                        (*state).scroll_lines =
                            clamp_summary_scroll((*state).scroll_lines, total_lines, visible_lines);
                        (*state).scroll_lines
                    };
                    let thumb =
                        summary_thumb_rect(&scrollbar, total_lines, visible_lines, scroll_lines);

                    unsafe {
                        FillRect(hdc, &client, (*state).bg_brush);
                        FillRect(hdc, &panel, (*state).panel_brush);
                        FrameRect(hdc, &panel, (*state).border_brush);
                        FillRect(hdc, &scrollbar, (*state).bg_brush);
                        FrameRect(hdc, &scrollbar, (*state).border_brush);
                        FillRect(hdc, &thumb, (*state).border_hot_brush);
                        SetBkMode(hdc, TRANSPARENT as i32);
                        SetTextColor(hdc, C_TEXT);
                        let old_font = SelectObject(hdc, (*state).body_font as _);
                        let start = scroll_lines as usize;
                        let end = (scroll_lines + visible_lines + 1).min(total_lines) as usize;
                        for (idx, line) in (&(*state).summary_lines)[start..end].iter().enumerate()
                        {
                            let top = text_rect.top + (idx as i32 * SUMMARY_LINE_HEIGHT);
                            let mut line_rect = RECT {
                                left: text_rect.left,
                                top,
                                right: text_rect.right,
                                bottom: (top + SUMMARY_LINE_HEIGHT).min(text_rect.bottom),
                            };
                            DrawTextW(
                                hdc,
                                if line.is_empty() {
                                    std::ptr::null()
                                } else {
                                    line.as_ptr()
                                },
                                line.len() as i32,
                                &mut line_rect,
                                DT_LEFT | DT_SINGLELINE | DT_VCENTER,
                            );
                        }
                        let _ = SelectObject(hdc, old_font);
                        EndPaint(hwnd, &ps);
                    }
                    0
                }
                WM_CLOSE => {
                    let state = get_state(hwnd);
                    if !state.is_null() && unsafe { (*state).dragging_thumb } {
                        unsafe {
                            (*state).dragging_thumb = false;
                            ReleaseCapture();
                        }
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
                            }
                            if !(*state).panel_brush.is_null() {
                                let _ = DeleteObject((*state).panel_brush as _);
                            }
                            if !(*state).title_font.is_null()
                                && (*state).title_font != GetStockObject(DEFAULT_GUI_FONT) as _
                            {
                                let _ = DeleteObject((*state).title_font as _);
                            }
                            if !(*state).body_font.is_null()
                                && (*state).body_font != GetStockObject(DEFAULT_GUI_FONT) as _
                            {
                                let _ = DeleteObject((*state).body_font as _);
                            }
                            if !(*state).border_brush.is_null() {
                                let _ = DeleteObject((*state).border_brush as _);
                            }
                            if !(*state).border_hot_brush.is_null() {
                                let _ = DeleteObject((*state).border_hot_brush as _);
                            }
                            (*state).done = true;
                        }
                    }
                    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
                    0
                }
                WM_ERASEBKGND => 1,
                _ => unsafe { DefWindowProcW(hwnd, msg, w, l) },
            }
        }

        let class_name = wide_z("ObsidianQ.SummaryDialog");
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

        let state = Box::new(SummaryDialogState {
            caption: wide_z(caption),
            title: wide_z(title),
            summary_text: wide_z(summary),
            summary_lines: split_summary_lines(summary),
            title_font: std::ptr::null_mut(),
            body_font: std::ptr::null_mut(),
            scroll_lines: 0,
            dragging_thumb: false,
            drag_offset: 0,
            done: false,
            bg_brush: unsafe { CreateSolidBrush(C_BG) },
            panel_brush: unsafe { CreateSolidBrush(rgb(11, 18, 15)) },
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
                404,
                535,
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
            show_error("ObsidianQ", "Unable to display package information.");
            return;
        }

        let mut msg: MSG = unsafe { std::mem::zeroed() };
        loop {
            let ok = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
            if ok <= 0 {
                break;
            }
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            if unsafe { (*state_ptr).done } {
                break;
            }
        }

        let _ = unsafe { Box::from_raw(state_ptr) };
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
        let len = path_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(path_buf.len());
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

    fn copy_range_to_file(
        src_path: &Path,
        offset: u64,
        length: u64,
        dst_path: &Path,
    ) -> io::Result<()> {
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

    fn run_delivery_extract(
        cli_path: &Path,
        package_zip: &Path,
        out_dir: &Path,
        password: &str,
    ) -> io::Result<bool> {
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

    fn run_delivery_json(
        cli_path: &Path,
        package_zip: &Path,
        subcommand: &str,
    ) -> io::Result<Value> {
        let output = Command::new(cli_path)
            .arg("delivery")
            .arg(subcommand)
            .arg(package_zip)
            .arg("--json")
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            return Err(io::Error::new(
                io::ErrorKind::Other,
                if detail.is_empty() {
                    format!("delivery {subcommand} failed")
                } else {
                    detail
                },
            ));
        }
        serde_json::from_slice(&output.stdout).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("parse delivery {subcommand} json: {e}"),
            )
        })
    }

    fn inspect_package_summary(cli_path: &Path, package_zip: &Path) -> io::Result<PackageSummary> {
        let inspect = run_delivery_json(cli_path, package_zip, "inspect")?;
        let _verify = run_delivery_json(cli_path, package_zip, "verify")?;
        let data = inspect
            .get("data")
            .and_then(|v| v.as_object())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "inspect response missing data"))?;

        let package_id = data
            .get("package_uuid")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("-")
            .to_string();
        let sender = data
            .get("sender_name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("Unknown Sender")
            .to_string();
        let created = data
            .get("created_utc")
            .and_then(|v| v.as_str())
            .map(format_utc_for_display)
            .unwrap_or_else(|| "-".to_string());
        let app_version = data
            .get("obsidianq_version")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("-")
            .to_string();
        let recipient_mode = data
            .get("recipient_mode")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("-")
            .to_string();
        let files = data
            .get("files")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|entry| {
                        entry
                            .get("path")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let signed = data
            .get("signed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let sender_identity_present = data
            .get("sender_fingerprint")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        Ok(PackageSummary {
            package_id,
            sender,
            created,
            app_version,
            recipient_mode,
            files,
            signed,
            sender_identity_present,
        })
    }

    fn format_utc_for_display(raw: &str) -> String {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return "-".to_string();
        }
        trimmed
            .replace('T', " ")
            .replace("+00:00", " UTC")
            .replace('Z', " UTC")
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
        let parent = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "output".to_string());
        let ext = path
            .extension()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

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
        let temp = std::env::temp_dir()
            .to_string_lossy()
            .replace('/', "\\")
            .to_lowercase();
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
        let _ = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .and_then(|mut f| f.write_all(line.as_bytes()));
    }
}

#[cfg(windows)]
fn main() {
    win_app::start();
}
