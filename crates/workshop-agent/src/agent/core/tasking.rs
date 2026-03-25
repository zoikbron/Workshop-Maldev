use core_defs::packer::MpTlv;

use core_defs::meterpreter::ENC_FLAG_AES256;
use rand::RngCore;

const TLV_TYPE_COMMAND_ID: u32 = 0x0002_0001;
const TLV_TYPE_STRING: u32 = 0x0001_000A;
const TLV_TYPE_SYM_KEY_TYPE: u32 = 0x0002_0227;
const TLV_TYPE_SYM_KEY: u32 = 0x0004_0228;

const ERROR_SUCCESS: u32 = 0;
const ERROR_NOT_SUPPORTED: u32 = 50;

const COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION: u32 = 16;
const COMMAND_ID_STD_PWD: u32 = 1001;

const COMMAND_ID_WORKSHOP_SET_BEACON: u32 = 9001;
const TLV_TYPE_WORKSHOP_SLEEP_MS: u32 = 0x2001_0001;
const TLV_TYPE_WORKSHOP_JITTER_PCT: u32 = 0x2001_0002;

/// Extrae un u32 big-endian de un TLV por tipo.
pub fn get_u32_be(tlvs: &[MpTlv], typ: u32) -> Option<u32> {
    /*
    ============================================================
    WORKSHOP: Implementar extracción de u32 de TLV
    ============================================================
    
    Pasos:
    1. Buscar el TLV con el tipo dado: tlvs.iter().find(|t| t.typ == typ)?
    2. Verificar que value.len() >= 4
    3. Retornar u32::from_be_bytes([value[0], value[1], value[2], value[3]])
    ============================================================
    */
    todo!("Implementar get_u32_be")
}

fn tlv_uint(typ: u32, v: u32) -> MpTlv {
    MpTlv {
        typ,
        value: v.to_be_bytes().to_vec(),
    }
}

fn tlv_raw(typ: u32, v: &[u8]) -> MpTlv {
    MpTlv {
        typ,
        value: v.to_vec(),
    }
}

fn tlv_wstring(typ: u32, s: &str) -> MpTlv {
    let mut out: Vec<u8> = Vec::new();
    for wc in s.encode_utf16() {
        out.extend_from_slice(&wc.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    MpTlv { typ, value: out }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchResult {
    pub result: u32,
    pub tlvs: Vec<MpTlv>,
    pub new_aes_key: Option<[u8; 32]>,
    pub new_sleep_ms: Option<u32>,
    pub new_jitter_pct: Option<u8>,
}

/// Dispatcher de comandos del C2.
///
/// Comandos soportados:
/// - COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION (16): Negociar clave AES
/// - COMMAND_ID_STD_PWD (1001): Obtener directorio actual
/// - COMMAND_ID_WORKSHOP_SET_BEACON (9001): Actualizar sleep/jitter
///
/// PASOS A IMPLEMENTAR:
/// 1. Extraer el command ID con get_u32_be(tlvs, TLV_TYPE_COMMAND_ID)
/// 2. Match sobre el command ID:
///    - Negotiate: generar clave AES aleatoria, retornar TLV con key
///    - StdPwd: obtener current_dir, retornar como wstring
///    - SetBeacon: extraer sleep_ms y jitter_pct, actualizar
///    - Default: retornar ERROR_NOT_SUPPORTED
pub fn dispatch_tlvs(tlvs: &[MpTlv]) -> DispatchResult {
    /*
    ============================================================
    WORKSHOP: Implementar dispatcher de comandos
    ============================================================
    
    Estructura del match:
    
    let cmd_id = get_u32_be(tlvs, TLV_TYPE_COMMAND_ID).unwrap_or(0);
    match cmd_id {
        COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION => {
            - let mut key = [0u8; 32];
            - rand::thread_rng().fill_bytes(&mut key);
            - Retornar DispatchResult con new_aes_key: Some(key)
              y tlvs con TLV_TYPE_SYM_KEY_TYPE y TLV_TYPE_SYM_KEY
        }
        COMMAND_ID_STD_PWD => {
            - let pwd = std::env::current_dir()...
            - Retornar DispatchResult con TLV_TYPE_STRING (wstring)
        }
        COMMAND_ID_WORKSHOP_SET_BEACON => {
            - Extraer sleep_ms con get_u32_be(tlvs, TLV_TYPE_WORKSHOP_SLEEP_MS)
            - Extraer jitter_pct (convertir a u8)
            - Retornar DispatchResult con new_sleep_ms y new_jitter_pct
        }
        _ => DispatchResult { result: ERROR_NOT_SUPPORTED, ... }
    }
    ============================================================
    */
    todo!("Implementar dispatch_tlvs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_u32_be_reads_first_4_bytes() {
        let tlvs = vec![MpTlv {
            typ: 0x1234,
            value: 0x11223344u32.to_be_bytes().to_vec(),
        }];
        assert_eq!(get_u32_be(&tlvs, 0x1234), Some(0x11223344));
    }

    #[test]
    fn get_u32_be_returns_none_for_missing() {
        let tlvs = vec![MpTlv { typ: 1, value: vec![0, 0, 0, 1] }];
        assert_eq!(get_u32_be(&tlvs, 2), None);
    }

    #[test]
    fn get_u32_be_returns_none_for_short() {
        let tlvs = vec![MpTlv { typ: 1, value: vec![1, 2, 3] }];
        assert_eq!(get_u32_be(&tlvs, 1), None);
    }

    #[test]
    fn dispatch_negotiate_returns_key() {
        let tlvs = vec![MpTlv {
            typ: TLV_TYPE_COMMAND_ID,
            value: COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION.to_be_bytes().to_vec(),
        }];
        let res = dispatch_tlvs(&tlvs);
        assert_eq!(res.result, ERROR_SUCCESS);
        assert!(res.new_aes_key.is_some());
        assert!(res.tlvs.iter().any(|t| t.typ == TLV_TYPE_SYM_KEY));
    }
}
