use std::sync::Arc;
use zeroize::Zeroize;
use sha2::{Digest, Sha256};

pub struct SecureBuffer {
    data: Vec<u8>,
    mask: [u8; 32],
}

impl SecureBuffer {

    pub fn new(plaintext: &[u8]) -> Self {
        use rand::RngCore;
        let mut mask = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut mask);
        let data = plaintext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 32])
            .collect();
        Self { data, mask }
    }

    pub fn decrypt(&self) -> Vec<u8> {
        self.data
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ self.mask[i % 32])
            .collect()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
        self.mask.zeroize();
    }
}

pub fn compute_self_hash() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let bytes = std::fs::read(&exe).ok()?;
    Some(hex::encode(Sha256::digest(&bytes)))
}

pub fn verify_self_integrity(expected_hex: &str) -> bool {
    compute_self_hash().map(|h| h == expected_hex).unwrap_or(false)
}

#[cfg(target_os = "windows")]
mod win {
    use std::sync::Arc;
    use winapi::shared::minwindef::{BOOL, DWORD};
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
    use winapi::um::processthreadsapi::{GetCurrentProcessId, SetProcessMitigationPolicy};
    use winapi::um::winuser::{GetClipboardOwner, GetClipboardSequenceNumber, GetWindowThreadProcessId};

    extern "system" {
        fn SetDefaultDllDirectories(DirectoryFlags: DWORD) -> BOOL;
    }

    const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: DWORD = 0x0000_1000;

    const PROCESS_HEAP_TERMINATE_ON_CORRUPTION_POLICY: u32 = 1;
    const PROCESS_STRICT_HANDLE_CHECK_POLICY:          u32 = 3;
    const PROCESS_EXTENSION_POINT_DISABLE_POLICY:      u32 = 7;

    pub fn apply_process_mitigations() {
        unsafe {

            SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);

            let heap: u32 = 1;
            SetProcessMitigationPolicy(
                PROCESS_HEAP_TERMINATE_ON_CORRUPTION_POLICY,
                &heap as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            );

            let strict: u32 = 0b11;
            SetProcessMitigationPolicy(
                PROCESS_STRICT_HANDLE_CHECK_POLICY,
                &strict as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            );

            let ext: u32 = 1;
            SetProcessMitigationPolicy(
                PROCESS_EXTENSION_POINT_DISABLE_POLICY,
                &ext as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            );
        }
    }

    unsafe fn is_fn_hooked(module: &[u8], fname: &[u8]) -> bool {
        let hmod = GetModuleHandleA(module.as_ptr() as *const i8);
        if hmod.is_null() { return false; }
        let proc = GetProcAddress(hmod, fname.as_ptr() as *const i8);
        if proc.is_null() { return false; }
        let bytes = std::slice::from_raw_parts(proc as *const u8, 6);

        bytes[0] == 0xE9
            || (bytes[0] == 0xFF && bytes[1] == 0x25)
            || bytes[0] == 0xE8
            || (bytes[0] == 0xCC && bytes[1] == 0xCC)
    }

    pub fn find_hooked_functions() -> Vec<&'static str> {
        const TARGETS: &[(&[u8], &[u8], &str)] = &[

            (b"ntdll.dll\0",       b"NtReadVirtualMemory\0",        "NtReadVirtualMemory"),
            (b"ntdll.dll\0",       b"NtWriteVirtualMemory\0",       "NtWriteVirtualMemory"),
            (b"ntdll.dll\0",       b"NtOpenProcess\0",              "NtOpenProcess"),
            (b"ntdll.dll\0",       b"NtQueryInformationProcess\0",  "NtQueryInformationProcess"),
            (b"ntdll.dll\0",       b"NtProtectVirtualMemory\0",     "NtProtectVirtualMemory"),
            (b"ntdll.dll\0",       b"NtCreateFile\0",               "NtCreateFile"),
            (b"ntdll.dll\0",       b"NtCreateThreadEx\0",           "NtCreateThreadEx"),
            (b"ntdll.dll\0",       b"LdrLoadDll\0",                 "LdrLoadDll"),

            (b"user32.dll\0",      b"SetWindowsHookExW\0",          "SetWindowsHookExW"),
            (b"user32.dll\0",      b"GetMessageW\0",                "GetMessageW"),
            (b"user32.dll\0",      b"TranslateMessage\0",           "TranslateMessage"),
            (b"user32.dll\0",      b"SendMessageW\0",               "SendMessageW"),

            (b"kernelbase.dll\0",  b"CreateFileW\0",                "CreateFileW"),
            (b"kernelbase.dll\0",  b"ReadFile\0",                   "ReadFile"),
            (b"kernelbase.dll\0",  b"WriteFile\0",                  "WriteFile"),
        ];
        unsafe {
            TARGETS
                .iter()
                .filter_map(|(module, fname, label)| {
                    if is_fn_hooked(module, fname) { Some(*label) } else { None }
                })
                .collect()
        }
    }

    pub fn detect_keyboard_hooks() -> bool {
        unsafe {
            is_fn_hooked(b"user32.dll\0", b"SetWindowsHookExW\0")
                || is_fn_hooked(b"user32.dll\0", b"GetMessageW\0")
                || is_fn_hooked(b"user32.dll\0", b"TranslateMessage\0")
                || is_fn_hooked(b"user32.dll\0", b"SendMessageW\0")
        }
    }

    pub fn clipboard_owner_pid() -> u32 {
        unsafe {
            let hwnd = GetClipboardOwner();
            if hwnd.is_null() { return 0; }
            let mut pid: DWORD = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            pid
        }
    }

    pub fn clipboard_seq() -> u32 {
        unsafe { GetClipboardSequenceNumber() }
    }

    pub fn start_clipboard_monitor(on_theft: Arc<dyn Fn() + Send + Sync + 'static>) {
        let our_pid = unsafe { GetCurrentProcessId() };

        std::thread::Builder::new()
            .name("clipboard-monitor".into())
            .spawn(move || {
                let mut last_seq = clipboard_seq();
                let mut we_owned = clipboard_owner_pid() == our_pid;

                loop {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let seq   = clipboard_seq();
                    let owner = clipboard_owner_pid();

                    if seq != last_seq {

                        if we_owned && owner != our_pid {
                            on_theft();
                        }
                        we_owned = owner == our_pid;
                        last_seq = seq;
                    } else if owner == our_pid {

                        we_owned = true;
                    }
                }
            })
            .ok();
    }
}

#[cfg(target_os = "windows")]
pub fn apply_process_mitigations() { win::apply_process_mitigations(); }
#[cfg(not(target_os = "windows"))]
pub fn apply_process_mitigations() {}

#[cfg(target_os = "windows")]
pub fn find_hooked_functions() -> Vec<&'static str> { win::find_hooked_functions() }
#[cfg(not(target_os = "windows"))]
pub fn find_hooked_functions() -> Vec<&'static str> { vec![] }

#[cfg(target_os = "windows")]
pub fn detect_keyboard_hooks() -> bool { win::detect_keyboard_hooks() }
#[cfg(not(target_os = "windows"))]
pub fn detect_keyboard_hooks() -> bool { false }

#[cfg(target_os = "windows")]
pub fn start_clipboard_monitor(on_theft: Arc<dyn Fn() + Send + Sync + 'static>) {
    win::start_clipboard_monitor(on_theft);
}
#[cfg(not(target_os = "windows"))]
pub fn start_clipboard_monitor(_on_theft: Arc<dyn Fn() + Send + Sync + 'static>) {}

#[cfg(target_os = "windows")]
pub fn clipboard_owner_pid() -> u32 { win::clipboard_owner_pid() }
#[cfg(not(target_os = "windows"))]
pub fn clipboard_owner_pid() -> u32 { 0 }

pub fn verify_vault_magic_canary() -> bool {
    let expected: &[u8; 4] = b"KPRS";
    let actual = crate::vault::MAGIC;
    expected
        .iter()
        .zip(actual.iter())
        .fold(0u8, |acc, (e, a)| acc | (e ^ a))
        == 0
}

