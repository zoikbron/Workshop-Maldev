use core::ffi::c_void;

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *const u16,
}

impl UNICODE_STRING {
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

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [u8; 16],
    pub Reserved2: [*mut c_void; 10],
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[derive(PartialEq)]
#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *const LIST_ENTRY,
    pub Blink: *const LIST_ENTRY,
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [u8; 8],
    pub Reserved2: [*const c_void; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

pub type PPS_POST_PROCESS_INIT_ROUTINE = Option<unsafe extern "system" fn()>;

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: u8, 
    pub Reserved3: *const c_void,
    pub ImageBaseAddress: *const c_void,
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

/* 
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
*/
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
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
    pub e_lfanew: u32,
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
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
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    Machine: u16,
    pub NumberOfSections: u16,
    TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub Reserved1: [usize; 2],
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: [usize; 2],
    pub DllBase: *const c_void,
    pub Reserved3: [usize; 2],
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}


