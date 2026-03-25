#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(nonstandard_style)]
#![allow(unused_assignments)]
#![allow(unused_must_use)]
extern crate alloc;

mod win_types;

use win_types::*;
use alloc::sync::Arc;
use alloc::ffi::CString;
use core::ffi::c_void;
// HINT: Necesitaremos core::arch::asm para leer el registro gs
// use core::arch::asm;
use std::{ptr::NonNull,sync::Mutex};

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;  // "MZ" en little-endian
const IMAGE_NT_SIGNATURE: u32 = 0x4550;   // "PE\0\0"
type LoadLibraryA = extern "system" fn(lpLibFileName: *const i8) -> *const c_void;






static MODULES: Mutex<Vec<Arc<Mutex<HMODULE>>>> = Mutex::new(Vec::new());


#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[derive(Debug)]
///Custom HMODULE structure
pub struct HMODULE {
    ///Module's Name
    pub Name: String,
    ///Module address represented in usize
    pub Addr: usize,
    pub pe: Option<PE>
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[derive(Debug)]
///Custom PE struct it just contains the sections pointer and not the data itself.
pub struct PE {
    pub dos_header: NonNull<IMAGE_DOS_HEADER>,
    pub nt_header: NonNull<IMAGE_NT_HEADERS64>,
    pub optional_header: NonNull<IMAGE_OPTIONAL_HEADER64>,
    pub data_directory: NonNull<IMAGE_DATA_DIRECTORY>,
    pub export_directory: NonNull<IMAGE_EXPORT_DIRECTORY>
}
unsafe impl Send for PE{}
unsafe impl Sync for PE{}

pub trait CastFunc{
 
 fn cast_to_function<T>(&self) -> T;

}

impl CastFunc for *const c_void {
    fn cast_to_function<T>(&self) -> T  {
     
unsafe {
        return core::mem::transmute_copy(self)
    }
        
    }
}
impl CastFunc for *mut c_void {
    fn cast_to_function<T>(&self) -> T  {
     
unsafe {
        return core::mem::transmute_copy(self)
    }
        
    }
}









/// Lee el registro gs en el offset especificado.
///
/// En x64 Windows, el registro `gs` apunta al Thread Environment Block (TEB).
/// El TEB contiene información del hilo actual y un puntero al PEB.
///
/// ## Offsets importantes del registro gs
///
/// | Offset | Estructura | Descripción |
/// |--------|------------|-------------|
/// | 0x00 | TEB* | Puntero al TEB actual |
/// | 0x30 | TEB* | Puntero al TEB (alias) |
/// | 0x60 | PEB* | Puntero al Process Environment Block |
/// | 0x68 | TEB* | Puntero al TEB (otro alias) |
///
/// ## Qué es el PEB
///
/// El PEB (Process Environment Block) es una estructura en memoria que contiene:
/// - Lista de módulos cargados (PEB_LDR_DATA)
/// - Argumentos de línea de comandos
/// - Variables de entorno
/// - Información del heap
/// - Flags de depuración
///
/// ## Implementación con asm!
///
/// ```rust,ignore
/// use core::arch::asm;
/// 
/// fn __readgsqword(offset: u64) -> u64 {
///     let out: u64;
///     unsafe {
///         asm!(
///             "mov rax, gs:[{offset}]",  // Lee gs:[offset] a rax
///             offset = in(reg) offset,    // Pasa offset como parámetro
///             out = out(reg) out,         // Resultado en 'out'
///             options(nostack, pure, readonly)
///         );
///     }
///     out
/// }
/// ```
///
/// ## Nota sobre seguridad
///
/// Esta función es `unsafe` porque accede directamente a memoria del kernel.
/// El registro gs solo es válido en modo usuario (ring 3).
fn __readgsqword(offset: u64) -> u64 {
    // TODO: Implementar lectura del registro gs
    // Pasos:
    // 1. Importar core::arch::asm al inicio del archivo
    // 2. Declarar variable out: u64
    // 3. Usar asm! con "mov {}, gs:[{}]"
    // 4. Retornar out
    todo!("Implementar lectura de gs register con asm!")
}



//This is a implementation without using std library for getting a handle (Es una implementacion sin std library para obtener un handle a un modulo del peb)
///Get a [`HMODULE`] to module in the peb.
/// New modules will be add to an array, otherwise it will increment the reference counter.
/// It queries the 0x60 gs register, go through the InMemoryOrderModuleList looking for a Module name provided to the function and return a pointer to the base address of the module.
///
/// ## Arquitectura de Memoria de Windows
///
/// ```text
/// gs:[0x60] ──> PEB (Process Environment Block)
///                    │
///                    ├── Ldr ──> PEB_LDR_DATA
///                    │              │
///                    │              ├── InLoadOrderModuleList (lista por orden de carga)
///                    │              ├── InMemoryOrderModuleList (lista por orden en memoria)  <-- USAMOS ESTA
///                    │              └── InInitializationOrderModuleList (lista por orden de init)
///                    │
///                    └── ... otros campos
/// ```
///
/// ## Estructuras involucradas
///
/// ### LIST_ENTRY (lista doblemente enlazada)
/// ```c
/// typedef struct _LIST_ENTRY {
///     struct _LIST_ENTRY *Flink;  // Puntero al siguiente
///     struct _LIST_ENTRY *Blink;  // Puntero al anterior
/// } LIST_ENTRY;
/// ```
///
/// ### LDR_DATA_TABLE_ENTRY (entrada de módulo)
/// ```c
/// typedef struct _LDR_DATA_TABLE_ENTRY {
///     LIST_ENTRY InLoadOrderLinks;           // Offset 0x00
///     LIST_ENTRY InMemoryOrderLinks;         // Offset 0x10  <-- InMemoryOrderModuleList apunta aquí
///     LIST_ENTRY InInitializationOrderLinks; // Offset 0x20
///     PVOID DllBase;                         // Offset 0x30  <-- Dirección base del módulo
///     PVOID EntryPoint;                      // Offset 0x38
///     SIZE_T SizeOfImage;                    // Offset 0x40
///     UNICODE_STRING FullDllName;            // Offset 0x48
///     UNICODE_STRING BaseDllName;            // Offset 0x58  <-- Nombre del DLL (solo nombre, sin path)
///     // ... más campos
/// } LDR_DATA_TABLE_ENTRY;
/// ```
///
/// ## Por qué InMemoryOrderModuleList?
///
/// Usamos InMemoryOrderModuleList porque:
/// 1. El puntero de la lista apunta al campo InMemoryOrderLinks (offset 0x10)
/// 2. Para obtener LDR_DATA_TABLE_ENTRY, restamos 0x10 (16 bytes) al puntero
/// 3. Esta lista está ordenada por la posición en memoria, lo que puede ser útil
///
/// ## PASOS A IMPLEMENTAR:
///
/// ### Paso 1: Obtener el PEB
/// ```rust,ignore
/// let peb_ptr: *const PEB = __readgsqword(0x60) as *const PEB;
/// ```
/// El PEB contiene toda la información del proceso.
///
/// ### Paso 2: Acceder a Ldr
/// ```rust,ignore
/// let ldr: &PEB_LDR_DATA = unsafe { &*(*peb_ptr).Ldr };
/// ```
/// PEB_LDR_DATA contiene las tres listas de módulos.
///
/// ### Paso 3: Obtener la cabeza de la lista
/// ```rust,ignore
/// let list_head: &LIST_ENTRY = &ldr.InMemoryOrderModuleList;
/// let first_entry: &LIST_ENTRY = unsafe { &*list_head.Flink };
/// ```
/// La lista es circular: el último elemento apunta al head.
///
/// ### Paso 4: Iterar la lista
/// ```rust,ignore
/// let mut current = first_entry;
/// while current != list_head {
///     // Procesar entrada
///     current = unsafe { &*current.Flink };
/// }
/// ```
///
/// ### Paso 5: Obtener LDR_DATA_TABLE_ENTRY
/// ```rust,ignore
/// // El puntero actual apunta a InMemoryOrderLinks (offset 0x10)
/// // Restamos 16 bytes para obtener el inicio de LDR_DATA_TABLE_ENTRY
/// let entry: *const LDR_DATA_TABLE_ENTRY = 
///     (current as *const LIST_ENTRY as usize - 16) as *const LDR_DATA_TABLE_ENTRY;
/// 
/// let name = unsafe { (*entry).BaseDllName.to_string() };
/// ```
///
/// ### Paso 6: Comparar y retornar
/// ```rust,ignore
/// if name.eq_ignore_ascii_case(module_name) {
///     let base = unsafe { (*entry).DllBase };
///     // Crear HMODULE y agregar al cache
///     return Some(arc_module);
/// }
/// ```
///
/// ## Manejo del cache
///
/// La función mantiene un cache global (MODULES) para evitar PEB walking repetido.
/// Si el módulo ya está en cache, retorna directamente.
/// Si no, lo busca, lo agrega al cache y retorna.
#[allow(non_snake_case)]
pub fn GetModuleHandle(ModuleName: Option<&str>)-> Option<Arc<Mutex<HMODULE>>>{
let mut modules_array  = match MODULES.lock(){
    Ok(p) => { p},
    Err(err) => {
        print!("Error With Locking module array: {}",err);
        return None
    }
};

// Primero buscar en el cache
for module_mutex in modules_array.iter(){
    let module = match module_mutex.lock(){
        Ok(p) => { p},
        Err(err) => {
            print!("Error with locking hmodule {}",err);
            return None

        }
    };

        match ModuleName {
            Some(name) => if module.Name.eq_ignore_ascii_case(name){ return Some(Arc::clone(&module_mutex))}
            None => if module.Name.contains("BaseImage") {return Some(Arc::clone(&module_mutex))} 
        }
        
    }
 

/*
============================================================
WORKSHOP: Implementar PEB Walking aquí
============================================================

Código de referencia para implementar:

// PASO 1: Obtener PEB desde gs:[0x60]
let MyPeb: *const PEB = __readgsqword(0x60) as *const PEB;

// PASO 2: Obtener PEB_LDR_DATA
let pLDR: &PEB_LDR_DATA = unsafe { &*(*MyPeb).Ldr };

// PASO 3: Obtener la lista InMemoryOrderModuleList
let List: &LIST_ENTRY = &pLDR.InMemoryOrderModuleList;

// PASO 4: Iterar la lista circular
let pFirst: &LIST_ENTRY = unsafe { &*List.Flink };
let mut iterator: &LIST_ENTRY = pFirst;

while iterator as *const _ != List as *const _ {
    // PASO 5: Obtener LDR_DATA_TABLE_ENTRY
    // IMPORTANTE: El puntero iterator apunta a InMemoryOrderLinks (offset 0x10)
    // Necesitamos retroceder 16 bytes para obtener el inicio del struct
    let pEntry: *const LDR_DATA_TABLE_ENTRY = 
        ((iterator as *const LIST_ENTRY as usize) - 16) as *const LDR_DATA_TABLE_ENTRY;
    
    // PASO 6: Obtener el nombre del módulo
    let entry_ref = unsafe { &*pEntry };
    let dll_name = entry_ref.BaseDllName.to_string();
    
    // PASO 7: Comparar con el nombre buscado
    let matches = match ModuleName {
        Some(name) => dll_name.eq_ignore_ascii_case(name),
        None => dll_name.contains("BaseImage"),  // Buscar ejecutable principal
    };
    
    if matches {
        // PASO 8: Crear HMODULE y agregar al cache
        let base_addr = entry_ref.DllBase as usize;
        let module = HMODULE {
            Name: dll_name,
            Addr: base_addr,
            pe: None,
        };
        let arc_module = Arc::new(Mutex::new(module));
        modules_array.push(Arc::clone(&arc_module));
        return Some(arc_module);
    }
    
    // Avanzar al siguiente elemento
    iterator = unsafe { &*iterator.Flink };
}

// Si llegamos aquí, no se encontró el módulo

============================================================
DIBUJO DE LA LISTA ENLAZADA:
============================================================

    ┌─────────────────────────────────────────────────────────┐
    │                    PEB_LDR_DATA                         │
    │  ┌─────────────────────────────────────────────────┐   │
    │  │     InMemoryOrderModuleList (LIST_ENTRY)         │   │
    │  │         Flink ─────────────────────────────┐     │   │
    │  │         Blink ─────────────────────────────┼──┐  │   │
    │  └────────────────────────────────────────────│──┼──┘   │
    └───────────────────────────────────────────────│──┼──────┘
                                                    │  │
         ┌──────────────────────────────────────────┘  │
         │                                             │
         ▼                                             │
    ┌────────────────────────────────┐                 │
    │  LDR_DATA_TABLE_ENTRY #1       │                 │
    │  ├─ InLoadOrderLinks           │                 │
    │  ├─ InMemoryOrderLinks ◄───────┼── iterator      │
    │  ├─ ...                        │                 │
    │  ├─ DllBase = 0x7FF...         │                 │
    │  └─ BaseDllName = "ntdll.dll"  │                 │
    │         │                      │                 │
    │         ▼ (Flink)              │                 │
    └─────────│──────────────────────┘                 │
              │                                        │
              ▼                                        │
    ┌────────────────────────────────┐                 │
    │  LDR_DATA_TABLE_ENTRY #2       │                 │
    │  ├─ InLoadOrderLinks           │                 │
    │  ├─ InMemoryOrderLinks         │                 │
    │  ├─ ...                        │                 │
    │  ├─ DllBase = 0x7FF...         │                 │
    │  └─ BaseDllName = "kernel32"   │                 │
    │         │                      │                 │
    │         ▼                      │                 │
    └─────────│──────────────────────┘                 │
              │                                        │
              ... (más módulos)                        │
              │                                        │
              ▼                                        │
    ┌────────────────────────────────┐                 │
    │  LDR_DATA_TABLE_ENTRY #N       │                 │
    │  ├─ InMemoryOrderLinks         │                 │
    │  │         Flink ──────────────────────────────┘
    │  │         Blink ◄──────────────────────────────┘ (vuelve al head)
    │  └─ ...                        │
    └────────────────────────────────┘

============================================================
*/

return None;
}

///wrapper LoadLibrary Function
pub fn LoadLibrary(library_name: &str)->Option<Arc<Mutex<HMODULE>>>{

let handle_mutex = match GetModuleHandle(Some("kernel32.dll")){
Some(p)=>p,
None => todo!()
};

/*let mut handle = match handle_mutex.lock(){
Ok(p)=>p,
Err(_) => todo!()
};*/
let string = CString::new(library_name).expect("Error getting the C-String");
let function: LoadLibraryA  = unsafe{ core::mem::transmute(GetProcAddress(handle_mutex,"LoadLibraryA").unwrap())};
let module = HMODULE {
Name: library_name.to_string(),
Addr: function(string.as_ptr()) as usize,
pe: None
};
let arc_module = Arc::new(Mutex::new(module));
let mut modules_array  = match MODULES.lock(){
    Ok(p) => p,
    Err(err) => {
        print!("Error With Locking module array: {}",err);
        return None
    }
};
modules_array.push(arc_module.clone());
return Some(arc_module);
}

pub fn RVA(base: usize, rva: usize) -> usize {

    return base + rva;

}


impl HMODULE {

/// Parsea el PE para obtener los punteros a las secciones importantes.
///
/// ## Estructura de un archivo PE (Portable Executable)
///
/// ```text
/// ┌─────────────────────────────────────┐
/// │         DOS Header (64 bytes)       │  ← self.Addr apunta aquí
/// │  e_magic = 0x5A4D ("MZ")            │
/// │  e_lfanew = offset al NT Headers    │
/// ├─────────────────────────────────────┤
/// │         DOS Stub (opcional)         │
/// ├─────────────────────────────────────┤
/// │         NT Headers                   │
/// │  Signature = 0x4550 ("PE\0\0")     │
/// │  FileHeader (20 bytes)              │
/// │  OptionalHeader (240 bytes x64)     │
/// │    ├─ DataDirectory[0] = Export     │
/// │    ├─ DataDirectory[1] = Import     │
/// │    └─ ...                           │
/// ├─────────────────────────────────────┤
/// │         Section Headers             │
/// │  .text, .data, .rdata, etc.         │
/// ├─────────────────────────────────────┤
/// │         Sections (datos)            │
/// │  .text (código)                     │
/// │  .data (datos inicializados)        │
/// │  .rdata (datos de solo lectura)      │
/// │  .edata (export directory)          │
/// │  .idata (import directory)          │
/// │  ...                                │
/// └─────────────────────────────────────┘
/// ```
///
/// ## Estructuras involucradas
///
/// ### IMAGE_DOS_HEADER (64 bytes)
/// ```c
/// typedef struct _IMAGE_DOS_HEADER {
///     WORD e_magic;    // Offset 0x00: "MZ" (0x5A4D)
///     // ... 28 WORDs ...
///     LONG e_lfanew;   // Offset 0x3C: Offset al NT Headers
/// } IMAGE_DOS_HEADER;
/// ```
///
/// ### IMAGE_NT_HEADERS64
/// ```c
/// typedef struct _IMAGE_NT_HEADERS64 {
///     DWORD Signature;                    // "PE\0\0" (0x4550)
///     IMAGE_FILE_HEADER FileHeader;        // 20 bytes
///     IMAGE_OPTIONAL_HEADER64 OptionalHeader;  // 240 bytes
/// } IMAGE_NT_HEADERS64;
/// ```
///
/// ### IMAGE_OPTIONAL_HEADER64 (campos relevantes)
/// ```c
/// typedef struct _IMAGE_OPTIONAL_HEADER64 {
///     // ... muchos campos ...
///     IMAGE_DATA_DIRECTORY DataDirectory[16];  // Array de 16 entradas
///     // [0] = Export Directory
///     // [1] = Import Directory
///     // [2] = Resource Directory
///     // ...
/// } IMAGE_OPTIONAL_HEADER64;
/// ```
///
/// ### IMAGE_DATA_DIRECTORY
/// ```c
/// typedef struct _IMAGE_DATA_DIRECTORY {
///     DWORD VirtualAddress;  // RVA (Relative Virtual Address)
///     DWORD Size;            // Tamaño del directorio
/// } IMAGE_DATA_DIRECTORY;
/// ```
///
/// ## PASOS A IMPLEMENTAR:
///
/// ### Paso 1: Verificar si ya fue parseado
/// ```rust,ignore
/// if self.pe.is_some() {
///     return Err(false);  // Ya parseado, no repetir
/// }
/// ```
///
/// ### Paso 2: Obtener DOS Header
/// ```rust,ignore
/// let dos_ptr = self.Addr as *const IMAGE_DOS_HEADER;
/// let dos = unsafe { &*dos_ptr };
/// ```
///
/// ### Paso 3: Verificar firma MZ
/// ```rust,ignore
/// if dos.e_magic != IMAGE_DOS_SIGNATURE {
///     return Err(false);  // No es un PE válido
/// }
/// ```
///
/// ### Paso 4: Obtener NT Headers
/// ```rust,ignore
/// // e_lfanew es el offset (RVA) al NT Headers desde el inicio del archivo
/// let nt_ptr = RVA(self.Addr, dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
/// let nt = unsafe { &*nt_ptr };
/// ```
///
/// ### Paso 5: Verificar firma PE
/// ```rust,ignore
/// if nt.Signature != IMAGE_NT_SIGNATURE {
///     return Err(false);  // No es un PE válido
/// }
/// ```
///
/// ### Paso 6: Obtener DataDirectory[0] (Export Directory)
/// ```rust,ignore
/// let data_dir = &nt.OptionalHeader.DataDirectory[0];
/// // data_dir.VirtualAddress es el RVA del Export Directory
/// // data_dir.Size es el tamaño del Export Directory
/// ```
///
/// ### Paso 7: Calcular dirección del Export Directory
/// ```rust,ignore
/// let export_ptr = RVA(self.Addr, data_dir.VirtualAddress as usize) 
///     as *const IMAGE_EXPORT_DIRECTORY;
/// ```
///
/// ### Paso 8: Crear struct PE con NonNull pointers
/// ```rust,ignore
/// self.pe = Some(PE {
///     dos_header: NonNull::new(dos_ptr as *mut _).unwrap(),
///     nt_header: NonNull::new(nt_ptr as *mut _).unwrap(),
///     optional_header: NonNull::new(&nt.OptionalHeader as *const _ as *mut _).unwrap(),
///     data_directory: NonNull::new(data_dir as *const _ as *mut _).unwrap(),
///     export_directory: NonNull::new(export_ptr as *mut _).unwrap(),
/// });
/// ```
///
/// ## Nota sobre RVA vs VA
///
/// - **VA (Virtual Address)**: Dirección absoluta en memoria
/// - **RVA (Relative Virtual Address)**: Offset desde la base del módulo
/// - Conversión: `VA = Base + RVA`
/// - La función `RVA(base, rva)` hace esta conversión
#[allow(non_snake_case)]
pub fn GetPESections(&mut self)->Result<bool,bool>{
    // TODO: Implementar parseo de PE headers
    // Seguir los pasos documentados arriba
    
    /*
    ============================================================
    WORKSHOP: Implementar parseo de PE headers
    ============================================================
    
    Código de referencia:
    
    // PASO 1: Verificar si ya está parseado
    if self.pe.is_some() {
        return Err(false);
    }
    
    // PASO 2: Obtener DOS header
    let dos_ptr: *const IMAGE_DOS_HEADER = self.Addr as *const IMAGE_DOS_HEADER;
    let dos = unsafe { &*dos_ptr };
    
    // PASO 3: Verificar firma MZ
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(false);
    }
    
    // PASO 4: Obtener NT headers usando e_lfanew
    let nt_ptr = RVA(self.Addr, dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let nt = unsafe { &*nt_ptr };
    
    // PASO 5: Verificar firma PE
    if nt.Signature != IMAGE_NT_SIGNATURE {
        return Err(false);
    }
    
    // PASO 6: Obtener DataDirectory[0] (Export Directory)
    let data_dir = &nt.OptionalHeader.DataDirectory[0];
    
    // PASO 7: Calcular dirección del Export Directory
    let export_ptr = RVA(self.Addr, data_dir.VirtualAddress as usize) 
        as *const IMAGE_EXPORT_DIRECTORY;
    
    // PASO 8: Crear struct PE
    self.pe = Some(PE {
        dos_header: NonNull::new(dos_ptr as *mut _).unwrap(),
        nt_header: NonNull::new(nt_ptr as *mut _).unwrap(),
        optional_header: NonNull::new(&nt.OptionalHeader as *const _ as *mut _).unwrap(),
        data_directory: NonNull::new(data_dir as *const _ as *mut _).unwrap(),
        export_directory: NonNull::new(export_ptr as *mut _).unwrap(),
    });
    
    return Ok(true);
    
    ============================================================
    */
    
   return Ok(true);
}

pub fn is_parsed(&self)-> Result<bool,bool>{
    match &self.pe{
        Some(_) => return Ok(true),
        None => return Err(false)

    }

}



}

/// Verifica si una dirección de función es un "forwarder" (apunta a otra DLL).
///
/// ## Qué es un Forwarder?
///
/// Un forwarder ocurre cuando una función de una DLL en realidad está
/// implementada en otra DLL. En lugar de código, el Export Table contiene
/// un string que indica dónde encontrar la función real.
///
/// ### Ejemplo típico
///
/// `kernel32.dll` exporta `AcquireSRWLockExclusive`, pero esta función
/// está implementada en `ntdll.dll`. El export de kernel32 contiene:
/// ```text
/// "NTDLL.RtlAcquireSRWLockExclusive"
/// ```
///
/// ## Cómo detectar un Forwarder
///
/// La dirección de la función (`funcaddr`) se compara con el rango del
/// Export Directory:
///
/// ```text
/// Si funcaddr está DENTRO del Export Directory:
///     base_address + ddirectory_va <= funcaddr < base_address + ddirectory_va + ddirectory_size
///     → Es un forwarder (el "puntero" en realidad es un string)
/// 
/// Si funcaddr está FUERA del Export Directory:
///     → Es una función normal (el puntero es código real)
/// ```
///
/// ## Formato del String de Forwarder
///
/// ```text
/// "DLLNAME.FuncName"     (ej: "NTDLL.RtlAcquireSRWLockExclusive")
/// "DLLNAME.#Ordinal"     (ej: "NTDLL.#123")
/// ```
///
/// El string es ASCII, null-terminated, y está dentro del Export Directory.
///
/// ## Argumentos
///
/// - `base_address`: Dirección base del módulo
/// - `ddirectory_va`: VirtualAddress del Export Directory (RVA)
/// - `ddirectory_size`: Tamaño del Export Directory
/// - `funcaddr`: Dirección de la función a verificar
///
/// ## Retorna
///
/// - `Ok(*const c_void)`: Dirección resuelta del forwarder
/// - `Err(false)`: No es forwarder, usar dirección original
///
/// ## PASOS A IMPLEMENTAR:
///
/// ### Paso 1: Calcular límites del Export Directory
/// ```rust,ignore
/// let export_start = base_address + ddirectory_va;
/// let export_end = export_start + ddirectory_size;
/// let func_addr_val = funcaddr as usize;
/// ```
///
/// ### Paso 2: Verificar si está dentro del rango
/// ```rust,ignore
/// if func_addr_val < export_start || func_addr_val >= export_end {
///     return Err(false);  // No es forwarder
/// }
/// ```
///
/// ### Paso 3: Leer el string del forwarder
/// ```rust,ignore
/// let forwarder_str = unsafe {
///     CStr::from_ptr(funcaddr as *const i8)
///         .to_str()
///         .ok()?  // Error parseando string
/// };
/// ```
///
/// ### Paso 4: Parsear "DLLNAME.FuncName"
/// ```rust,ignore
/// let parts: Vec<&str> = forwarder_str.split('.').collect();
/// if parts.len() != 2 {
///     return Err(false);  // Formato inválido
/// }
/// let dll_name = parts[0];
/// let func_name = parts[1];
/// ```
///
/// ### Paso 5: Resolver el módulo
/// ```rust,ignore
/// // Agregar ".dll" si no tiene extensión
/// let full_dll_name = if dll_name.contains('.') {
///     dll_name.to_string()
/// } else {
///     format!("{}.dll", dll_name)
/// };
/// 
/// let module = GetModuleHandle(Some(&full_dll_name))
///     .or_else(|| LoadLibrary(&full_dll_name))?;
/// ```
///
/// ### Paso 6: Resolver la función recursivamente
/// ```rust,ignore
/// let resolved = GetProcAddress(module, func_name)?;
/// return Ok(resolved);
/// ```
pub fn get_forwarder(base_address: usize, ddirectory_va: usize, ddirectory_size: usize, funcaddr: *const c_void) -> Result<*const c_void, bool> {
    /*
    ============================================================
    WORKSHOP: Implementar detección de forwarders
    ============================================================
    
    Código de referencia:
    
    use core::ffi::CStr;
    
    // PASO 1: Calcular límites del Export Directory
    let export_start = base_address + ddirectory_va;
    let export_end = export_start + ddirectory_size;
    let func_addr_val = funcaddr as usize;
    
    // PASO 2: Verificar si es forwarder
    if func_addr_val < export_start || func_addr_val >= export_end {
        return Err(false);  // No es forwarder, dirección válida
    }
    
    // PASO 3: Leer string del forwarder
    let forwarder_str = match unsafe {
        CStr::from_ptr(funcaddr as *const i8).to_str()
    } {
        Ok(s) => s,
        Err(_) => return Err(false),
    };
    
    // PASO 4: Parsear "DLLNAME.FuncName"
    let dot_pos = match forwarder_str.find('.') {
        Some(p) => p,
        None => return Err(false),
    };
    let dll_name = &forwarder_str[..dot_pos];
    let func_name = &forwarder_str[dot_pos + 1..];
    
    // PASO 5: Resolver módulo
    let full_dll = if dll_name.contains('.') {
        dll_name.to_string()
    } else {
        format!("{}.dll", dll_name)
    };
    
    let module = match GetModuleHandle(Some(&full_dll)) {
        Some(m) => m,
        None => LoadLibrary(&full_dll)?,
    };
    
    // PASO 6: Resolver función recursivamente
    match GetProcAddress(module, func_name) {
        Some(addr) => Ok(addr),
        None => Err(false),
    }
    
    ============================================================
    */
    Err(false)
}


/// Busca una función por nombre en el Export Table de un módulo.
///
/// ## Estructura del Export Directory
///
/// El Export Directory contiene tres arrays paralelos que permiten
/// buscar funciones por nombre:
///
/// ```text
/// IMAGE_EXPORT_DIRECTORY
/// ├── NumberOfFunctions    → Número total de funciones exportadas
/// ├── NumberOfNames        → Número de funciones con nombre (≤ NumberOfFunctions)
/// ├── AddressOfFunctions   → RVA de array de RVAs a funciones
/// ├── AddressOfNames       → RVA de array de RVAs a strings de nombres
/// └── AddressOfNameOrdinals → RVA de array de ordinales (índices)
///
/// Array de Nombres (AddressOfNames):
/// ┌────────────────────────────────────────┐
/// │ [0] RVA → "FunctionA\0"               │
/// │ [1] RVA → "FunctionB\0"               │
/// │ [2] RVA → "FunctionC\0"               │
/// │ ...                                    │
/// └────────────────────────────────────────┘
///
/// Array de Ordinales (AddressOfNameOrdinals):
/// ┌────────────────────────────────────────┐
/// │ [0] = 5  ← FunctionA está en índice 5   │
/// │ [1] = 2  ← FunctionB está en índice 2   │
/// │ [2] = 7  ← FunctionC está en índice 7   │
/// │ ...                                    │
/// └────────────────────────────────────────┘
///
/// Array de Funciones (AddressOfFunctions):
/// ┌────────────────────────────────────────┐
/// │ [0] RVA → código de función sin nombre  │
/// │ [1] RVA → código de función sin nombre  │
/// │ [2] RVA → código de FunctionB          │
/// │ ...                                    │
/// │ [5] RVA → código de FunctionA          │
/// │ ...                                    │
/// │ [7] RVA → código de FunctionC          │
/// └────────────────────────────────────────┘
/// ```
///
/// ## Algoritmo de Búsqueda
///
/// 1. Iterar AddressOfNames buscando el string
/// 2. Usar el índice para obtener el ordinal de AddressOfNameOrdinals
/// 3. Usar el ordinal como índice en AddressOfFunctions
/// 4. Calcular VA = Base + AddressOfFunctions[ordinal]
///
/// ## Por qué dos arrays (Names y Ordinals)?
///
/// - `AddressOfNames` está ordenado alfabéticamente para búsqueda rápida
/// - `AddressOfFunctions` NO está ordenado (mantiene orden original)
/// - `AddressOfNameOrdinals` conecta ambos: índice en Names → índice en Functions
///
/// ## Argumentos
///
/// - `hmodule`: Handle al módulo (Arc<Mutex<HMODULE>>)
/// - `ProcName`: Nombre de la función a buscar
///
/// ## Retorna
///
/// - `Some(*const c_void)`: Dirección de la función
/// - `None`: Función no encontrada o error
///
/// ## PASOS A IMPLEMENTAR:
///
/// ### Paso 1: Bloquear el módulo
/// ```rust,ignore
/// let mut module = hmodule.lock().ok()?;
/// ```
///
/// ### Paso 2: Verificar si está parseado
/// ```rust,ignore
/// if module.pe.is_none() {
///     module.GetPESections().ok()?;
/// }
/// ```
///
/// ### Paso 3: Obtener punteros del PE
/// ```rust,ignore
/// let ppe = module.pe.as_ref()?;
/// let export_dir = unsafe { &*ppe.export_directory.as_ptr() };
/// let base = module.Addr;
/// ```
///
/// ### Paso 4: Obtener arrays del Export Directory
/// ```rust,ignore
/// let names_ptr = RVA(base, export_dir.AddressOfNames as usize) as *const u32;
/// let ordinals_ptr = RVA(base, export_dir.AddressOfNameOrdinals as usize) as *const u16;
/// let funcs_ptr = RVA(base, export_dir.AddressOfFunctions as usize) as *const u32;
/// ```
///
/// ### Paso 5: Iterar buscando el nombre
/// ```rust,ignore
/// for i in 0..export_dir.NumberOfNames {
///     // Obtener RVA del string
///     let name_rva = unsafe { *names_ptr.add(i as usize) };
///     let name_ptr = RVA(base, name_rva as usize) as *const i8;
///     
///     // Comparar string
///     let name = unsafe { CStr::from_ptr(name_ptr) };
///     if name.to_str().ok()? == ProcName {
///         // Encontrado! Obtener ordinal
///         let ordinal = unsafe { *ordinals_ptr.add(i as usize) } as usize;
///         
///         // Obtener dirección de función
///         let func_rva = unsafe { *funcs_ptr.add(ordinal) };
///         let func_addr = RVA(base, func_rva as usize) as *const c_void;
///         
///         // Verificar si es forwarder
///         let data_dir = unsafe { &*ppe.data_directory.as_ptr() };
///         return match get_forwarder(
///             base,
///             data_dir.VirtualAddress as usize,
///             data_dir.Size as usize,
///             func_addr
///         ) {
///             Ok(forwarded) => Some(forwarded),
///             Err(_) => Some(func_addr),
///         };
///     }
/// }
/// ```
///
/// ### Paso 6: No encontrado
/// ```rust,ignore
/// None
/// ```
pub fn GetProcAddress(hmodule: Arc<Mutex<HMODULE>>, ProcName: &str) -> Option<*const c_void> {
    /*
    ============================================================
    WORKSHOP: Implementar resolución de exports
    ============================================================
    
    Código de referencia:
    
    use core::ffi::CStr;
    
    // PASO 1: Bloquear módulo
    let mut module = hmodule.lock().ok()?;
    
    // PASO 2: Verificar si está parseado
    if module.pe.is_none() {
        module.GetPESections().ok()?;
    }
    
    // PASO 3: Obtener punteros del PE
    let ppe = module.pe.as_ref()?;
    let export_dir = unsafe { &*ppe.export_directory.as_ptr() };
    let base = module.Addr;
    
    // PASO 4: Obtener arrays del Export Directory
    let names_ptr = RVA(base, export_dir.AddressOfNames as usize) as *const u32;
    let ordinals_ptr = RVA(base, export_dir.AddressOfNameOrdinals as usize) as *const u16;
    let funcs_ptr = RVA(base, export_dir.AddressOfFunctions as usize) as *const u32;
    
    // PASO 5: Iterar buscando el nombre
    for i in 0..export_dir.NumberOfNames {
        let name_rva = unsafe { *names_ptr.add(i as usize) };
        let name_ptr = RVA(base, name_rva as usize) as *const i8;
        let name = unsafe { CStr::from_ptr(name_ptr) };
        
        if name.to_str().ok()? == ProcName {
            // Encontrado! Obtener ordinal y dirección
            let ordinal = unsafe { *ordinals_ptr.add(i as usize) } as usize;
            let func_rva = unsafe { *funcs_ptr.add(ordinal) };
            let func_addr = RVA(base, func_rva as usize) as *const c_void;
            
            // Verificar forwarder
            let data_dir = unsafe { &*ppe.data_directory.as_ptr() };
            return match get_forwarder(
                base,
                data_dir.VirtualAddress as usize,
                data_dir.Size as usize,
                func_addr
            ) {
                Ok(forwarded) => Some(forwarded),
                Err(_) => Some(func_addr),
            };
        }
    }
    
    // PASO 6: No encontrado
    None
    
    ============================================================
    */
    None
}
    

#[cfg(test)]
mod tests {
use super::*;

 #[test]
 fn test_getModule(){

   let opmodule  = GetModuleHandle(Some("kernel32.dll"));
   assert!(opmodule.is_some());
   let module  = opmodule.unwrap();
   let p = module.lock();
   assert!(p.is_ok());
 }
 
 #[test]
 fn test_parsing(){

    let opmodule  = GetModuleHandle(Some("kernel32.dll"));
    assert!(opmodule.is_some());

    let module  = opmodule.unwrap();
    let mut p = module.lock();
    assert!(p.is_ok());
    p.as_mut().unwrap().GetPESections();
    print!("{:#?}",p.as_mut().unwrap());


/*
PVOID MapViewOfFile3(
  [in]                HANDLE                 FileMapping,
  [in]                HANDLE                 Process,
  [in, optional]      PVOID                  BaseAddress,
  [in]                ULONG64                Offset,
  [in]                SIZE_T                 ViewSize,
  [in]                ULONG                  AllocationType,
  [in]                ULONG                  PageProtection,
  [in, out, optional] MEM_EXTENDED_PARAMETER *ExtendedParameters,
  [in]                ULONG                  ParameterCount
);
*/

 } 
#[test]
fn test_NULL(){
let opmodule = GetModuleHandle(None);
assert!(opmodule.is_some());
let module  = opmodule.unwrap();
let p = module.lock();
assert!(p.is_ok());
println!("{:p}", p.as_ref().unwrap().Addr as *const c_void);

}
#[test]
fn test_getProcAddress(){
    let opmodule  = GetModuleHandle(Some("kernelbase.dll"));
    assert!(opmodule.is_some());
    let module  = opmodule.unwrap();

   let func = GetProcAddress(module,"MapViewOfFile3");
   assert!(func.is_some());
   print!("{:#?}",func.unwrap());
 }
#[test]
fn test_reference_count(){
    let opmodule = GetModuleHandle(None);
    assert!(opmodule.is_some());
    assert_eq!(Arc::strong_count(opmodule.as_ref().unwrap()),2);
    let opmodule2 = GetModuleHandle(None);
    assert!(opmodule2.is_some());
    assert_eq!(Arc::strong_count(opmodule.as_ref().unwrap()),3);
    core::mem::drop(opmodule2);
    assert_eq!(Arc::strong_count(opmodule.as_ref().unwrap()),2);
}
#[test]
fn test_forwarder(){

    let opmodule  = GetModuleHandle(Some("kernel32.dll"));
    assert!(opmodule.is_some());

    let module  = opmodule.unwrap();
  
    let func = GetProcAddress(module,"AcquireSRWLockExclusive");
    assert!(func.is_some());

   print!("{:#?}",func.unwrap());

}


}

