//! # Estructuras de Windows para PEB Walking y PE Parsing
//!
//! Este módulo define las estructuras de Windows necesarias para:
//! - PEB Walking (enumerar módulos cargados)
//! - PE Parsing (leer Export Table)
//!
//! ## Referencias
//!
//! - PEB: https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
//! - PE Format: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

use core::ffi::c_void;

// ============================================================================
// ESTRUCTURAS PARA PEB WALKING
// ============================================================================

/// String Unicode de Windows (UTF-16LE).
///
/// Usado por el PEB para nombres de módulos y rutas.
///
/// ## Campos
///
/// - `Length`: Longitud en **bytes** (no caracteres)
/// - `MaximumLength`: Capacidad del buffer en bytes
/// - `Buffer`: Puntero a array de u16 (UTF-16LE)
///
/// ## Ejemplo
///
/// ```text
/// UNICODE_STRING { Length: 24, MaximumLength: 26, Buffer: 0x... }
/// Buffer apunta a: L'k' L'e' L'r' L'n' L'e' L'l' L'3' L'2' L'.' L'd' L'l' L'l'
///                  (kernel32.dll = 12 caracteres = 24 bytes)
/// ```
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct UNICODE_STRING {
    /// Longitud del string en bytes (sin terminador NUL).
    /// NOTA: Es bytes, no caracteres. Dividir por 2 para obtener length en u16.
    pub Length: u16,
    
    /// Capacidad del buffer en bytes.
    pub MaximumLength: u16,
    
    /// Puntero al buffer de caracteres UTF-16LE.
    /// Puede ser null si el string está vacío.
    pub Buffer: *const u16,
}

impl UNICODE_STRING {
    /// Convierte el UNICODE_STRING a un String de Rust.
    ///
    /// ## Retorna
    ///
    /// - `Some(String)`: String convertido exitosamente
    /// - `None`: Buffer vacío o puntero nulo
    ///
    /// ## Nota sobre Length
    ///
    /// `Length` está en bytes, pero el buffer contiene u16s.
    /// Por eso dividimos por 2: `len = Length / 2`
    pub fn to_string(&self) -> Option<String> {
        if self.Buffer as usize == 0 || self.Length as usize == 0 {
            print!("This shit is not even a Unicode String boy\n");
            return None;
        }
        let len: usize = (self.Length / 2) as usize;
        let slizi: &[u16] = unsafe { core::slice::from_raw_parts(self.Buffer, len) };

        Some(
            core::char::decode_utf16(slizi.iter().cloned())
                .collect::<Result<String, _>>()
                .ok()
                .unwrap(),
        )
    }
}

/// Parámetros de proceso del PEB.
///
/// Contiene información sobre el ejecutable y línea de comandos.
/// No se usa directamente en PEB walking, pero es parte del PEB.
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [u8; 16],
    pub Reserved2: [*mut c_void; 10],
    /// Ruta completa del ejecutable.
    pub ImagePathName: UNICODE_STRING,
    /// Línea de comandos del proceso.
    pub CommandLine: UNICODE_STRING,
}

/// Entrada de lista doblemente enlazada.
///
/// Usada en múltiples estructuras de Windows para crear listas circulares.
///
/// ## Campos
///
/// - `Flink`: Forward link - puntero al **siguiente** elemento
/// - `Blink`: Backward link - puntero al **anterior** elemento
///
/// ## Lista circular
///
/// ```text
///     ┌───┐    ┌───┐    ┌───┐    ┌───┐
///     │ A │───>│ B │───>│ C │───>│ D │
///     │   │<───│   │<───│   │<───│   │
///     └───┘    └───┘    └───┘    └───┘
///       ^                          │
///       └──────────────────────────┘
///            (lista circular)
/// ```
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[derive(PartialEq)]
#[repr(C)]
pub struct LIST_ENTRY {
    /// Puntero al siguiente elemento de la lista.
    pub Flink: *const LIST_ENTRY,
    
    /// Puntero al elemento anterior de la lista.
    pub Blink: *const LIST_ENTRY,
}

/// Datos del loader del PEB.
///
/// Contiene las tres listas de módulos cargados:
/// - InLoadOrderModuleList
/// - InMemoryOrderModuleList ← **Usamos esta**
/// - InInitializationOrderModuleList
///
/// ## Offset de InMemoryOrderModuleList
///
/// En el struct PEB_LDR_DATA, InMemoryOrderModuleList está en el offset 0x20
/// (después de Reserved1[8] + Reserved2[3] = 8 + 24 = 32 bytes)
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [u8; 8],
    pub Reserved2: [*const c_void; 3],
    /// Lista de módulos ordenados por posición en memoria.
    /// Cada entrada es un LIST_ENTRY que apunta a InMemoryOrderLinks
    /// dentro de un LDR_DATA_TABLE_ENTRY.
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

/// Tipo de función para rutina de post-inicialización.
pub type PPS_POST_PROCESS_INIT_ROUTINE = Option<unsafe extern "system" fn()>;

/// Process Environment Block (PEB).
///
/// Estructura principal que contiene información del proceso.
/// Se obtiene leyendo `gs:[0x60]` en x64 Windows.
///
/// ## Campos importantes
///
/// - `BeingDebugged`: 1 si el proceso está siendo depurado
/// - `ImageBaseAddress`: Dirección base del ejecutable
/// - `Ldr`: Puntero a PEB_LDR_DATA (lista de módulos)
///
/// ## Acceso
///
/// ```rust,ignore
/// let peb: *const PEB = __readgsqword(0x60) as *const PEB;
/// let ldr = unsafe { &*(*peb).Ldr };
/// ```
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    /// Flag de depuración: 1 si hay debugger adjunto.
    pub BeingDebugged: u8,
    pub Reserved2: u8, 
    pub Reserved3: *const c_void,
    /// Dirección base del ejecutable principal.
    pub ImageBaseAddress: *const c_void,
    /// Puntero a PEB_LDR_DATA - contiene lista de módulos cargados.
    pub Ldr: *const PEB_LDR_DATA,
    pub ProcessParameters: RTL_USER_PROCESS_PARAMETERS,
    pub Reserved4: [*const c_void; 3],
    pub AtlThunkSListPtr: *const c_void,
    pub Reserved5: *const c_void,
    pub Reserved6: u32,
    pub Reserved7: *const c_void,
    pub Reserved8: u32,
    pub AtlThunkSListPtr32: u32,
    pub Reserved9: [*const c_void; 45],
    pub Reserved10: [u8; 96],
    pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
    pub Reserved11: [u8; 128],
    pub Reserved12: *const c_void,
    pub SessionId: u32,
}

// ============================================================================
// ESTRUCTURAS PARA PE PARSING
// ============================================================================

/// Directorio de exportaciones de un PE.
///
/// Contiene las tablas necesarias para resolver funciones por nombre.
///
/// ## Campos clave
///
/// - `NumberOfNames`: Cantidad de funciones con nombre
/// - `AddressOfNames`: RVA del array de RVAs a strings de nombres
/// - `AddressOfNameOrdinals`: RVA del array de ordinales (índices)
/// - `AddressOfFunctions`: RVA del array de RVAs de funciones
///
/// ## Algoritmo de búsqueda
///
/// ```text
/// for i in 0..NumberOfNames:
///     nombre = leer_string(AddressOfNames[i])
///     si nombre == buscado:
///         ordinal = AddressOfNameOrdinals[i]
///         func_rva = AddressOfFunctions[ordinal]
///         return base + func_rva
/// ```
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    /// RVA del nombre del DLL (string ASCII).
    pub Name: u32,
    /// Valor base para ordinales exportados por índice.
    pub Base: u32,
    /// Número total de funciones en AddressOfFunctions.
    pub NumberOfFunctions: u32,
    /// Número de funciones con nombre (≤ NumberOfFunctions).
    pub NumberOfNames: u32,
    /// RVA del array de RVAs a strings de nombres.
    /// Array de u32[NumberOfNames], ordenado alfabéticamente.
    pub AddressOfFunctions: u32,
    /// RVA del array de RVAs a strings de nombres.
    /// Cada entrada es un RVA a un string ASCII null-terminated.
    pub AddressOfNames: u32,
    /// RVA del array de ordinales (índices en AddressOfFunctions).
    /// Array de u16[NumberOfNames].
    pub AddressOfNameOrdinals: u32,
}

/// Header DOS de un archivo PE (legacy).
///
/// Los primeros 64 bytes de todo PE contienen este header.
///
/// ## Campos importantes
///
/// - `e_magic`: Firma "MZ" (0x5A4D) - indica que es un ejecutable
/// - `e_lfanew`: Offset (en bytes) al NT Headers
///
/// ## Uso
///
/// ```rust,ignore
/// let dos = base_addr as *const IMAGE_DOS_HEADER;
/// if (*dos).e_magic != 0x5A4D { /* no es PE */ }
/// let nt_offset = (*dos).e_lfanew;  // RVA al NT Headers
/// ```
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    /// Firma "MZ" (0x5A4D). Verificar siempre primero.
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    /// Offset (RVA) al NT Headers. Sumar a base_addr para obtener puntero.
    pub e_lfanew: u32,
}

/// Entrada del Data Directory.
///
/// El OptionalHeader contiene un array de 16 de estas entradas.
/// Cada entrada describe una sección del PE.
///
/// ## Índices importantes
///
/// | Índice | Directorio |
/// |--------|------------|
/// | 0 | Export Directory |
/// | 1 | Import Directory |
/// | 2 | Resource Directory |
/// | 3 | Exception Directory |
///
/// ## Uso
///
/// ```rust,ignore
/// let export_dir = optional_header.DataDirectory[0];
/// let export_addr = base + export_dir.VirtualAddress;
/// ```
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    /// RVA (Relative Virtual Address) del directorio.
    /// Sumar a base_addr para obtener dirección absoluta.
    pub VirtualAddress: u32,
    /// Tamaño del directorio en bytes.
    pub Size: u32,
}

/// Optional Header de 64 bits (PE32+).
///
/// Contiene información crítica del ejecutable.
///
/// ## Campos importantes
///
/// - `ImageBase`: Dirección base preferida del módulo
/// - `AddressOfEntryPoint`: RVA del punto de entrada
/// - `DataDirectory`: Array de 16 directorios (Export, Import, etc.)
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    /// RVA del punto de entrada (main/WinMain).
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    /// Dirección base preferida del módulo en memoria.
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    /// Array de 16 directorios de datos.
    /// [0] = Export, [1] = Import, [2] = Resource, etc.
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

/// File Header del PE.
///
/// Parte del NT Headers, contiene información básica del archivo.
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    Machine: u16,
    /// Número de secciones (.text, .data, .rdata, etc.).
    pub NumberOfSections: u16,
    TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    /// Tamaño del Optional Header que sigue.
    pub SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

/// NT Headers de 64 bits (PE32+).
///
/// Estructura principal que contiene toda la información del PE.
///
/// ## Firma
///
/// `Signature` debe ser 0x4550 ("PE\0\0").
///
/// ## Ubicación
///
/// Se encuentra en: `base_addr + DOS_HEADER.e_lfanew`
///
/// ```rust,ignore
/// let nt = (base + dos.e_lfanew) as *const IMAGE_NT_HEADERS64;
/// if (*nt).Signature != 0x4550 { /* no es PE válido */ }
/// ```
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    /// Firma "PE\0\0" (0x4550). Verificar siempre.
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    /// Optional Header con DataDirectory.
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

/// Entrada de módulo en la lista del PEB.
///
/// Cada módulo cargado tiene una de estas entradas en las listas
/// del PEB_LDR_DATA.
///
/// ## Layout de offsets (x64)
///
/// | Offset | Campo |
/// |--------|-------|
/// | 0x00 | InLoadOrderLinks |
/// | 0x10 | InMemoryOrderLinks ← La lista apunta aquí |
/// | 0x20 | InInitializationOrderLinks |
/// | 0x30 | DllBase |
/// | 0x48 | FullDllName |
/// | 0x58 | BaseDllName |
///
/// ## Obtener entrada desde InMemoryOrderLinks
///
/// El puntero de la lista apunta a `InMemoryOrderLinks` (offset 0x10).
/// Para obtener el inicio del struct, restamos 16 bytes:
///
/// ```rust,ignore
/// let entry = (iterator as usize - 16) as *const LDR_DATA_TABLE_ENTRY;
/// let name = (*entry).BaseDllName.to_string();
/// let base = (*entry).DllBase;
/// ```
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub Reserved1: [usize; 2],
    /// Links para la lista InMemoryOrderModuleList.
    /// IMPORTANTE: El puntero de la lista apunta a este campo.
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: [usize; 2],
    /// Dirección base del módulo en memoria.
    pub DllBase: *const c_void,
    pub Reserved3: [usize; 2],
    /// Ruta completa del DLL (ej: C:\Windows\System32\kernel32.dll).
    pub FullDllName: UNICODE_STRING,
    /// Nombre del DLL sin ruta (ej: kernel32.dll).
    /// Usar para comparar con el nombre buscado.
    pub BaseDllName: UNICODE_STRING,
}


