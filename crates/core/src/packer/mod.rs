use std::vec::Vec;

// =============================
// Meterpreter TLV (classic) I/O
// =============================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpTlv {
    pub typ: u32,
    pub value: Vec<u8>,
}

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

#[inline]
pub fn mp_put_uint(tlvs: &mut Vec<MpTlv>, typ: u32, v: u32) { tlvs.push(MpTlv { typ, value: v.to_be_bytes().to_vec() }); }
#[inline]
pub fn mp_put_qword(tlvs: &mut Vec<MpTlv>, typ: u32, v: u64) { tlvs.push(MpTlv { typ, value: v.to_be_bytes().to_vec() }); }
#[inline]
pub fn mp_put_bool(tlvs: &mut Vec<MpTlv>, typ: u32, v: bool) { let x: u32 = if v {1} else {0}; tlvs.push(MpTlv { typ, value: x.to_be_bytes().to_vec() }); }
#[inline]
pub fn mp_put_stringz(tlvs: &mut Vec<MpTlv>, typ: u32, s: &str) { let mut b = s.as_bytes().to_vec(); b.push(0); tlvs.push(MpTlv { typ, value: b }); }
#[inline]
pub fn mp_put_bytes(tlvs: &mut Vec<MpTlv>, typ: u32, b: &[u8]) { tlvs.push(MpTlv { typ, value: b.to_vec() }); }

#[inline]
pub fn mp_get_uint(tlvs: &[MpTlv], typ: u32) -> Option<u32> { let t = tlvs.iter().find(|t| t.typ == typ)?; if t.value.len() < 4 { return None; } Some(u32::from_be_bytes([t.value[0],t.value[1],t.value[2],t.value[3]])) }
#[inline]
pub fn mp_get_qword(tlvs: &[MpTlv], typ: u32) -> Option<u64> { let t = tlvs.iter().find(|t| t.typ == typ)?; if t.value.len() < 8 { return None; } Some(u64::from_be_bytes([t.value[0],t.value[1],t.value[2],t.value[3],t.value[4],t.value[5],t.value[6],t.value[7]])) }
#[inline]
pub fn mp_get_bool(tlvs: &[MpTlv], typ: u32) -> Option<bool> { mp_get_uint(tlvs, typ).map(|v| v!=0) }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackerError {
    UnexpectedEof,
}
