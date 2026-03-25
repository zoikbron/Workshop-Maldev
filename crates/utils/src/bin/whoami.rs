fn main() {
    use core::ffi::c_void;

    use get_proc::{CastFunc, GetModuleHandle, GetProcAddress, LoadLibrary};

    type BOOL = i32;

    // https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-getusernamew
    type GetUserNameW = extern "system" fn(lp_buffer: *mut u16, pcb_buffer: *mut u32) -> BOOL;

    let module = match GetModuleHandle(Some("advapi32.dll")) {
        Some(m) => m,
        None => match LoadLibrary("advapi32.dll") {
            Some(m) => m,
            None => {
                eprintln!("failed to load advapi32.dll");
                std::process::exit(1);
            }
        },
    };

    let addr = match GetProcAddress(module, "GetUserNameW") {
        Some(p) => p,
        None => {
            eprintln!("failed to resolve GetUserNameW");
            std::process::exit(1);
        }
    };

    // We rely on the existing CastFunc impl for raw pointers.
    let get_user_name_w: GetUserNameW = (addr as *const c_void).cast_to_function();

    // Per docs, pcbBuffer is in TCHARs (u16 chars here), including null terminator.
    let mut buf: Vec<u16> = vec![0u16; 256];
    let mut len: u32 = buf.len() as u32;

    let ok = get_user_name_w(buf.as_mut_ptr(), &mut len);
    if ok == 0 {
        eprintln!("GetUserNameW failed");
        std::process::exit(1);
    }

    let used = buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(buf.len());

    let user = String::from_utf16_lossy(&buf[..used]);
    println!("{}", user);
}
