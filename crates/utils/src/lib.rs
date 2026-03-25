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
/// En x64 Windows, gs:[0x60] apunta al PEB (Process Environment Block).
///
/// TODO: Implementar usando asm! macro para leer el registro.
/// Hint: usar "mov {}, gs:[{}]" con out(reg) e in(reg)
fn __readgsqword(offset: u64) -> u64 {
    // TODO: Implementar lectura del registro gs
    // let out: u64;
    // unsafe { asm!(...) }
    // return out;
    todo!("Implementar lectura de gs register con asm!")
}



//This is a implementation without using std library for getting a handle (Es una implementacion sin std library para obtener un handle a un modulo del peb)
///Get a [`HMODULE`] to module in the peb.
/// New modules will be add to an array, otherwise it will increment the reference counter.
/// It queries the 0x60 gs register, go through the InMemoryOrderModuleList looking for a Module name provided to the function and return a pointer to the base address of the module.
///
/// PASOS A IMPLEMENTAR:
/// 1. Obtener el PEB desde gs:[0x60]
/// 2. Acceder a PEB->Ldr (PEB_LDR_DATA)
/// 3. Iterar InMemoryOrderModuleList (LIST_ENTRY doblemente enlazada)
/// 4. Para cada entrada, obtener LDR_DATA_TABLE_ENTRY
/// 5. Comparar BaseDllName con el nombre buscado
/// 6. Retornar DllBase cuando se encuentre
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

Pasos:
1. let MyPeb: *const PEB = __readgsqword(0x60) as *const PEB;
2. let pLDR: &PEB_LDR_DATA = unsafe{ &*(*MyPeb).Ldr };
3. let List: &LIST_ENTRY = &(*pLDR).InMemoryOrderModuleList;
4. Iterar la lista:
   - let pFirst: &LIST_ENTRY = unsafe {&*(*List).Flink};
   - let mut iterator: &LIST_ENTRY = pFirst;
   - while iterator != List { ... }
5. Para cada entrada:
   - let pEntry: *const LDR_DATA_TABLE_ENTRY = ((iterator as *const LIST_ENTRY) as usize - 16) as *const LDR_DATA_TABLE_ENTRY;
   - Comparar (*pEntry).BaseDllName.to_string() con ModuleName
   - Si coincide, crear HMODULE y agregar al cache

Hint: el offset 16 es el tamaño de los campos antes de InMemoryOrderLinks en LDR_DATA_TABLE_ENTRY
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
/// PASOS A IMPLEMENTAR:
/// 1. Verificar si ya fue parseado (self.pe.is_some())
/// 2. Obtener DOS header: self.Addr as *const IMAGE_DOS_HEADER
/// 3. Verificar firma MZ (0x5A4D)
/// 4. Obtener NT headers: base + e_lfanew
/// 5. Verificar firma PE (0x4550)
/// 6. Obtener OptionalHeader y DataDirectory[0] (Export Directory)
/// 7. Calcular RVA al Export Directory
/// 8. Poblar struct PE con NonNull pointers
#[allow(non_snake_case)]
pub fn GetPESections(&mut self)->Result<bool,bool>{
    // TODO: Verificar si ya está parseado
    // if self.pe.is_some() { return Err(false); }
    
    /*
    ============================================================
    WORKSHOP: Implementar parseo de PE headers
    ============================================================
    
    Pasos:
    1. let dos_pointer: *const IMAGE_DOS_HEADER = self.Addr as *const IMAGE_DOS_HEADER;
    2. Verificar (*dos_pointer).e_magic == IMAGE_DOS_SIGNATURE
    3. let nt_pointer = RVA(self.Addr, (*dos_pointer).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    4. Verificar (*nt_pointer).Signature == IMAGE_NT_SIGNATURE
    5. let pDataDirectory = &(*nt_pointer).OptionalHeader.DataDirectory[0];
    6. let export_dir = RVA(self.Addr, pDataDirectory.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    7. self.pe = Some(PE { ... });
    
    Hint: Usar NonNull::new(ptr as *mut _).unwrap() para crear los NonNull
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
/// Los forwarders están dentro del rango del Export Directory.
///
/// Si es forwarder: parsea "DLLNAME.FuncName" y resuelve recursivamente.
/// Si no: retorna Err(false) para usar la dirección original.
pub fn get_forwarder(base_address: usize, ddirectory_va: usize, ddirectory_size: usize, funcaddr: *const c_void) -> Result<*const c_void, bool> {
    /*
    ============================================================
    WORKSHOP: Implementar detección de forwarders
    ============================================================
    
    Un forwarder ocurre cuando funcaddr está DENTRO del export directory:
    base_address + ddirectory_va <= funcaddr < base_address + ddirectory_va + ddirectory_size
    
    Si es forwarder:
    1. let forwarder_string = CStr::from_ptr(funcaddr as *const i8).to_str()
    2. Parsear "DLLNAME.FuncName" (split en '.')
    3. Resolver el módulo con GetModuleHandle o LoadLibrary
    4. Resolver la función con GetProcAddress recursivamente
    ============================================================
    */
    Err(false)
}


/// Busca una función por nombre en el Export Table de un módulo.
///
/// PASOS A IMPLEMENTAR:
/// 1. Obtener el módulo del mutex y verificar si está parseado
/// 2. Obtener punteros del Export Directory:
///    - AddressOfNames (array de RVA a strings)
///    - AddressOfNameOrdinals (array de ordinales)
///    - AddressOfFunctions (array de RVA de funciones)
/// 3. Iterar por NumberOfNames, comparando strings
/// 4. Cuando se encuentre, usar el ordinal para obtener el índice en AddressOfFunctions
/// 5. Calcular la dirección final: base + AddressOfFunctions[ordinal]
/// 6. Verificar si es forwarder con get_forwarder()
pub fn GetProcAddress(hmodule: Arc<Mutex<HMODULE>>, ProcName: &str) -> Option<*const c_void> {
    /*
    ============================================================
    WORKSHOP: Implementar resolución de exports
    ============================================================
    
    Pasos:
    1. let module = hmodule.lock().ok()?;
    2. Si module.pe.is_none(), llamar module.GetPESections()
    3. let ppe = module.pe.as_ref()?;
    4. Obtener punteros:
       - pName = RVA(address, export_dir.AddressOfNames) as *const u32
       - pOrdinals = RVA(address, export_dir.AddressOfNameOrdinals) as *const u16
       - pFuncs = RVA(address, export_dir.AddressOfFunctions) as *const u32
    5. for n in 0..NumberOfNames:
       - let name = CStr::from_ptr(RVA(address, *pName.add(n)))
       - if name == ProcName:
         - let ordinal = *pOrdinals.add(n)
         - let funcaddr = RVA(address, *pFuncs.add(ordinal as usize))
         - Verificar forwarder
         - return Some(funcaddr)
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

