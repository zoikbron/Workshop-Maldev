//! # Meterpreter TLV (Type-Length-Value) Protocol
//!
//! Este módulo implementa el protocolo de serialización TLV usado por Meterpreter
//! para comunicación entre agentes y servidores C2.
//!
//! ## Formato TLV
//!
//! Cada TLV tiene la siguiente estructura en wire-format:
//! ```text
//! +----------------+----------------+------------------+
//! | Length (4 bytes) | Type (4 bytes) | Value (N bytes) |
//! +----------------+----------------+------------------+
//! ```
//!
//! - **Length**: Tamaño total en bytes (incluye header de 8 bytes + value)
//! - **Type**: Identificador del tipo de dato (ver constantes TLV_TYPE_*)
//! - **Value**: Payload variable
//!
//! Todos los valores están en big-endian (network byte order).
//!
//! ## Uso en el Workshop
//!
//! El agente y el servidor usan este formato para:
//! - Enviar comandos (dispatch)
//! - Recibir resultados
//! - Negociar encriptación AES
//! - Configurar beaconing (sleep/jitter)
//!
//! ## Ejemplo de uso
//!
//! ```rust
//! use core_defs::packer::{MpTlv, mp_pack_tlvs, mp_unpack_tlvs};
//!
//! // Crear TLVs
//! let tlvs = vec![
//!     MpTlv { typ: 0x0002_0001, value: vec![0, 0, 0, 16] }, // Command ID = 16
//!     MpTlv { typ: 0x0004_0228, value: vec![0u8; 32] },      // AES Key
//! ];
//!
//! // Serializar a bytes
//! let packed = mp_pack_tlvs(&tlvs);
//!
//! // Deserializar
//! let (decoded, _) = mp_unpack_tlvs(&packed).unwrap();
//! ```

use std::vec::Vec;

/// Representa un TLV (Type-Length-Value) individual.
///
/// ## Campos
///
/// - `typ`: Identificador de 4 bytes que indica el tipo de dato.
///   Los tipos siguen el formato Meterpreter:
///   - Bytes 0-1: Grupo (core, std, etc.)
///   - Bytes 2-3: Tipo específico (uint, string, raw, etc.)
/// - `value`: Payload variable con el contenido del dato.
///
/// ## Constantes de tipo comunes
///
/// | Constante | Valor | Descripción |
/// |-----------|-------|-------------|
/// | TLV_TYPE_COMMAND_ID | 0x0002_0001 | ID del comando a ejecutar |
/// | TLV_TYPE_STRING | 0x0001_000A | String UTF-16LE (Windows) |
/// | TLV_TYPE_SYM_KEY_TYPE | 0x0002_0227 | Tipo de encriptación |
/// | TLV_TYPE_SYM_KEY | 0x0004_0228 | Clave simétrica AES |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpTlv {
    pub typ: u32,
    pub value: Vec<u8>,
}

/// Serializa una lista de TLVs a bytes.
///
/// ## Proceso
///
/// Para cada TLV:
/// 1. Calcula length = 8 (header) + value.len()
/// 2. Escribe length como u32 big-endian (4 bytes)
/// 3. Escribe typ como u32 big-endian (4 bytes)
/// 4. Escribe value bytes directamente
///
/// ## Wire Format
///
/// ```text
/// [len1][typ1][val1...][len2][typ2][val2...]...
/// ```
///
/// ## Argumentos
///
/// - `tlvs`: Slice de TLVs a serializar
///
/// ## Retorna
///
/// Vector de bytes con todos los TLVs concatenados.
pub fn mp_pack_tlvs(tlvs: &[MpTlv]) -> Vec<u8> {
    let mut out = Vec::new();
    for t in tlvs {
        let len = (8 + t.value.len()) as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&t.typ.to_be_bytes());
        out.extend_from_slice(&t.value);
    }
    out
}

/// Deserializa bytes a una lista de TLVs.
///
/// ## Proceso
///
/// 1. Lee 4 bytes de length (big-endian)
/// 2. Lee 4 bytes de type (big-endian)
/// 3. Lee (length - 8) bytes de value
/// 4. Repite hasta consumir el buffer
///
/// ## Argumentos
///
/// - `buf`: Bytes a deserializar
///
/// ## Retorna
///
/// - `Ok((Vec<MpTlv>, usize))`: TLVs deserializados y bytes consumidos
/// - `Err(PackerError::UnexpectedEof)`: Si el buffer está truncado
///
/// ## Errores
///
/// Retorna error si:
/// - Length < 8 (mínimo header)
/// - No hay suficientes bytes para el value declarado
pub fn mp_unpack_tlvs(buf: &[u8]) -> core::result::Result<(Vec<MpTlv>, usize), PackerError> {
    let mut idx = 0usize;
    let mut out: Vec<MpTlv> = Vec::new();
    while idx + 8 <= buf.len() {
        let len = u32::from_be_bytes([buf[idx], buf[idx+1], buf[idx+2], buf[idx+3]]) as usize;
        let typ = u32::from_be_bytes([buf[idx+4], buf[idx+5], buf[idx+6], buf[idx+7]]);
        idx += 8;
        if len < 8 || idx + (len - 8) > buf.len() { return Err(PackerError::UnexpectedEof); }
        let val_len = len - 8;
        let val = buf[idx .. idx + val_len].to_vec();
        out.push(MpTlv { typ, value: val });
        idx += val_len;
    }
    Ok((out, idx))
}

// ============================
// Funciones helper para crear TLVs
// ============================

/// Agrega un u32 big-endian como TLV.
#[inline]
pub fn mp_put_uint(tlvs: &mut Vec<MpTlv>, typ: u32, v: u32) { 
    tlvs.push(MpTlv { typ, value: v.to_be_bytes().to_vec() }); 
}

/// Agrega un u64 big-endian como TLV.
#[inline]
pub fn mp_put_qword(tlvs: &mut Vec<MpTlv>, typ: u32, v: u64) { 
    tlvs.push(MpTlv { typ, value: v.to_be_bytes().to_vec() }); 
}

/// Agrega un bool como TLV (0 = false, 1 = true).
#[inline]
pub fn mp_put_bool(tlvs: &mut Vec<MpTlv>, typ: u32, v: bool) { 
    let x: u32 = if v {1} else {0}; 
    tlvs.push(MpTlv { typ, value: x.to_be_bytes().to_vec() }); 
}

/// Agrega un string null-terminated como TLV.
#[inline]
pub fn mp_put_stringz(tlvs: &mut Vec<MpTlv>, typ: u32, s: &str) { 
    let mut b = s.as_bytes().to_vec(); 
    b.push(0); 
    tlvs.push(MpTlv { typ, value: b }); 
}

/// Agrega bytes raw como TLV.
#[inline]
pub fn mp_put_bytes(tlvs: &mut Vec<MpTlv>, typ: u32, b: &[u8]) { 
    tlvs.push(MpTlv { typ, value: b.to_vec() }); 
}

// ============================
// Funciones helper para leer TLVs
// ============================

/// Extrae un u32 big-endian de un TLV por tipo.
///
/// Busca el primer TLV con el tipo dado y parsea sus primeros 4 bytes.
#[inline]
pub fn mp_get_uint(tlvs: &[MpTlv], typ: u32) -> Option<u32> { 
    let t = tlvs.iter().find(|t| t.typ == typ)?; 
    if t.value.len() < 4 { return None; } 
    Some(u32::from_be_bytes([t.value[0],t.value[1],t.value[2],t.value[3]])) 
}

/// Extrae un u64 big-endian de un TLV por tipo.
#[inline]
pub fn mp_get_qword(tlvs: &[MpTlv], typ: u32) -> Option<u64> { 
    let t = tlvs.iter().find(|t| t.typ == typ)?; 
    if t.value.len() < 8 { return None; } 
    Some(u64::from_be_bytes([t.value[0],t.value[1],t.value[2],t.value[3],t.value[4],t.value[5],t.value[6],t.value[7]])) 
}

/// Extrae un bool de un TLV por tipo.
#[inline]
pub fn mp_get_bool(tlvs: &[MpTlv], typ: u32) -> Option<bool> { 
    mp_get_uint(tlvs, typ).map(|v| v!=0) 
}

/// Errores posibles durante el parsing de TLVs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackerError {
    /// El buffer terminó inesperadamente antes de completar un TLV.
    UnexpectedEof,
}
