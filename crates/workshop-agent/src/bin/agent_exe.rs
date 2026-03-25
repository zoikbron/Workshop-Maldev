#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let mut url = std::env::var("MP_URL").unwrap_or_else(|_| "http://127.0.0.1:8080/register".to_string());
    let mut sleep_ms: Option<u64> = None;
    let mut jitter_pct: Option<u8> = None;
    let mut max_iter: Option<u64> = None;

    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--url" => {
                if let Some(v) = args.next() {
                    url = v;
                }
            }
            "--sleep-ms" => {
                if let Some(v) = args.next() {
                    if let Ok(n) = v.parse::<u64>() {
                        sleep_ms = Some(n);
                    }
                }
            }
            "--jitter-pct" => {
                if let Some(v) = args.next() {
                    if let Ok(n) = v.parse::<u8>() {
                        jitter_pct = Some(n);
                    }
                }
            }
            "--max-iter" => {
                if let Some(v) = args.next() {
                    if let Ok(n) = v.parse::<u64>() {
                        max_iter = Some(n);
                    }
                }
            }
            "--help" | "-h" => {
                return;
            }
            _ => {
                if !a.starts_with('-') {
                    url = a;
                }
            }
        }
    }

    let code = workshop_agent::agent::build::exe::run_with_options(&url, sleep_ms, jitter_pct, max_iter);
    std::process::exit(code as i32);
}
