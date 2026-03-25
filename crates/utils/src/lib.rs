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
use core::arch::asm;
use std::{ptr::NonNull,sync::Mutex};

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x4550;
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
fn __readgsqword(offset: u64) -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "mov {}, gs:[{}]",
            out(reg) out,
            in(reg) offset,
        );
    }
    out
}



//This is a implementation without using std library for getting a handle (Es una implementacion sin std library para obtener un handle a un modulo del peb)
///Get a [`HMODULE`] to module in the peb.
/// New modules will be add to an array, otherwise it will increment the reference counter.
/// It queries the 0x60 gs register, go through the InMemoryOrderModuleList looking for a Module name provided to the function and return a pointer to the base address of the module.
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
 

let MyPeb: *const PEB = __readgsqword(0x60) as *const PEB;

let pLDR: *const PEB_LDR_DATA = unsafe {(*MyPeb).Ldr};

let pLDR: &PEB_LDR_DATA = unsafe{ &*(*MyPeb).Ldr};

let List: &LIST_ENTRY = &(*pLDR).InMemoryOrderModuleList;

let pFirst: &LIST_ENTRY = unsafe {&*(*List).Flink};
let mut iterator: &LIST_ENTRY = pFirst;
let lsize: usize = 16;
while iterator != List{


let pEntry: *const LDR_DATA_TABLE_ENTRY = ((iterator as *const LIST_ENTRY) as usize - lsize) as *const LDR_DATA_TABLE_ENTRY;

unsafe {  
let toutf8: String = match (*pEntry).BaseDllName.to_string(){
        Some(utf8) => utf8,
        None =>{ println!("Something happened here"); 
    return None}
};

if toutf8.eq_ignore_ascii_case(ModuleName.unwrap_or_default()) {
    let current_module: HMODULE = HMODULE{
    Name:  toutf8,
    Addr: (*pEntry).DllBase as usize,
    pe: None
    };
    let arc_module= Arc::new(Mutex::new(current_module));
    modules_array.push(arc_module.clone());
    return Some(arc_module);
}
}




iterator = unsafe{&*(*iterator).Flink};
}
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
#[allow(non_snake_case)]
pub fn GetPESections(&mut self)->Result<bool,bool>{
    if self.pe.is_some(){
        return Err(false);
    }
    
    let dos_pointer: *const IMAGE_DOS_HEADER =  self.Addr as *const IMAGE_DOS_HEADER;
    let pIMAGE_DOS_HEADER: &IMAGE_DOS_HEADER = unsafe{ &*dos_pointer};

    let nt_pointer: *const IMAGE_NT_HEADERS64 = RVA(self.Addr , (*pIMAGE_DOS_HEADER).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let pIMAGE_NT_HEADERS: &IMAGE_NT_HEADERS64  = unsafe {&*nt_pointer}; 

    if (*pIMAGE_DOS_HEADER).e_magic != IMAGE_DOS_SIGNATURE{
       return Err(false)
    }
    if (*pIMAGE_NT_HEADERS).Signature != IMAGE_NT_SIGNATURE{
      return Err(false)
    }

    let pOptionalHeader: &IMAGE_OPTIONAL_HEADER64 = &(*pIMAGE_NT_HEADERS).OptionalHeader;
    let optional_pointer: *const IMAGE_OPTIONAL_HEADER64 = &(*pIMAGE_NT_HEADERS).OptionalHeader as *const IMAGE_OPTIONAL_HEADER64;

    let data_pointer: *const IMAGE_DATA_DIRECTORY = &(*pOptionalHeader).DataDirectory[0] as *const IMAGE_DATA_DIRECTORY;
    let pDataDirectory: &IMAGE_DATA_DIRECTORY = &(*pOptionalHeader).DataDirectory[0];

    let Export_pointer: *const IMAGE_EXPORT_DIRECTORY = RVA(self.Addr , pDataDirectory.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;

    self.pe = Some(PE {
    dos_header: NonNull::new(dos_pointer as *mut IMAGE_DOS_HEADER).unwrap(),
    nt_header: NonNull::new(nt_pointer as *mut IMAGE_NT_HEADERS64).unwrap(), 
    optional_header: NonNull::new(optional_pointer as *mut IMAGE_OPTIONAL_HEADER64).unwrap(),
    data_directory: NonNull::new(data_pointer as *mut IMAGE_DATA_DIRECTORY).unwrap(),
    export_directory: NonNull::new(Export_pointer as *mut IMAGE_EXPORT_DIRECTORY).unwrap() });

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
pub fn get_forwarder(base_address: usize, ddirectory_va: usize, ddirectory_size: usize, funcaddr: *const c_void) -> Result<*const c_void, bool> {
    unsafe {
        if ((funcaddr as usize) < (base_address + ddirectory_va + ddirectory_size) as usize) && ((funcaddr as usize) > (base_address + ddirectory_va) as usize) {
            #[cfg(debug_assertions)] {
                print!("This is forwarder\n");
            }
            let forwarder_string = core::ffi::CStr::from_ptr(funcaddr as *const i8).to_str().unwrap();
            #[cfg(debug_assertions)] {
                print!("This is the forwarder string: {}\n", forwarder_string);
            }
            let mut iterator = forwarder_string.split(".");
            let module_name = iterator.next().unwrap();
            let module_name = (module_name.to_owned() + ".dll").to_string();
            let function_name = iterator.next().unwrap();
            #[cfg(debug_assertions)] {
                print!("This is the module name: {}\n", module_name);
                print!("This is the function name: {}\n", function_name);
            }
            let opmodule = match GetModuleHandle(Some(&module_name)) {
                Some(p) => Some(p),
                None => LoadLibrary(&module_name)
            };
            if opmodule.is_none() {
                println!("Module not found");
                return Err(false);
            }
            let module = opmodule.unwrap();
            let func = GetProcAddress(module, function_name);
            if func.is_none() {
                println!("Function not found");
                return Err(false);
            }
            let func = func.unwrap();
            return Ok(func);
        }
    }
    Err(false)
}


/// Busca una función por nombre en el Export Table de un módulo.
pub fn GetProcAddress(hmodule: Arc<Mutex<HMODULE>>, ProcName: &str) -> Option<*const c_void> {
    let mut address = 0;
    let pName: *const u32;
    let pOrdinals: *const u16;
    let pFuncs: *const u32;
    let number_of_names: u32;
    let mut ddirectory_va = 0;
    let mut ddirectory_size = 0;
    {
        let p = hmodule.lock();
        if p.is_err() {
            return None;
        }
        let mut module = p.unwrap();
        
        if module.pe.is_none() {
            module.GetPESections();   
        }
        let ppe = match &module.pe {
            Some(pe) => pe,
            None => return None
        };
        address = module.Addr;
        pName = unsafe { RVA(address, ppe.export_directory.as_ref().AddressOfNames as usize) as *const u32 };
        pOrdinals = unsafe { RVA(address, ppe.export_directory.as_ref().AddressOfNameOrdinals as usize) as *const u16 };
        pFuncs = unsafe { RVA(address, ppe.export_directory.as_ref().AddressOfFunctions as usize) as *const u32 };
        number_of_names = unsafe { ppe.export_directory.as_ref().NumberOfNames };
        ddirectory_va = unsafe { ppe.data_directory.as_ref().VirtualAddress as usize };
        ddirectory_size = unsafe { ppe.data_directory.as_ref().Size as usize };
    }

    unsafe {
        for n in 0..number_of_names {
            let funcname = core::ffi::CStr::from_ptr((address + *pName.add(n as usize) as usize) as *const i8);
            let str = funcname.to_str().unwrap_or_default();
            if str == ProcName {
                let funcaddr: *const c_void = (address + *pFuncs.add(*pOrdinals.add(n as usize) as usize) as usize) as *const c_void;
                let funcaddr = match get_forwarder(address, ddirectory_va, ddirectory_size, funcaddr) {
                    Ok(p) => p,
                    Err(_) => funcaddr
                };
                #[cfg(debug_assertions)] {
                    print!("RVA to Function: {:x}\n", *pFuncs.add(*pOrdinals.add(n as usize) as usize) as u32);
                    print!("Function {:p}\n", funcaddr);
                }
                return Some(funcaddr);
            }
        }
    }
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

