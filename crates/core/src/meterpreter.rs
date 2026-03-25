use std::vec::Vec;
use rand::RngCore;
use cipher::{KeyIvInit, block_padding::Pkcs7, BlockEncryptMut, BlockDecryptMut};
use aes::Aes256;
use cbc::{Encryptor, Decryptor};

use crate::packer::{MpTlv, mp_pack_tlvs, mp_unpack_tlvs};

pub const ENC_FLAG_NONE: u32 = 0x0;
pub const ENC_FLAG_AES256: u32 = 0x1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpHeader {
    pub xor_key: [u8; 4],
    pub session_guid: [u8; 16],
    pub enc_flags: u32,
    pub length: u32,    // big-endian on the wire
    pub typ: u32,       // big-endian on the wire
}

fn xor_bytes(xk: [u8; 4], data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() { *b ^= xk[i % 4]; }
}

pub fn encode_frame(session_guid: [u8; 16], pkt_type: u32, tlvs: &[MpTlv], aes_key: Option<&[u8; 32]>) -> Vec<u8> {
    // Build TLV payload in classic BE format
    let mut payload = mp_pack_tlvs(tlvs);

    let mut enc_flags = ENC_FLAG_NONE;
    if let Some(key) = aes_key {
        // AES-256-CBC with PKCS7, prepend IV
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let enc = Encryptor::<Aes256>::new_from_slices(key, &iv).expect("bad key/iv");
        let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(&payload);
        let mut with_iv = Vec::with_capacity(16 + ct.len());
        with_iv.extend_from_slice(&iv);
        with_iv.extend_from_slice(&ct);
        payload = with_iv;
        enc_flags = ENC_FLAG_AES256;
    }

    // Header.length includes sizeof(TlvHeader) (8) + payload bytes (IV+ciphertext or plaintext)
    let length_field: u32 = 8u32 + (payload.len() as u32);

    let mut header = [0u8; 32];
    // xor_key
    let xor_key = {
        let x = rand::random::<u32>();
        x.to_le_bytes()
    };
    header[0..4].copy_from_slice(&xor_key);
    // session_guid
    header[4..20].copy_from_slice(&session_guid);
    // enc_flags, length, typ (BE)
    header[20..24].copy_from_slice(&enc_flags.to_be_bytes());
    header[24..28].copy_from_slice(&length_field.to_be_bytes());
    header[28..32].copy_from_slice(&pkt_type.to_be_bytes());

    // Build full buffer then XOR tail (skip xor_key itself)
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&payload);
    xor_bytes(xor_key, &mut out[4..]);
    out
}

pub fn decode_frame(frame: &[u8], aes_key: Option<&[u8; 32]>) -> Result<(MpHeader, Vec<MpTlv>), &'static str> {
    if frame.len() < 32 { return Err("short frame"); }
    // Copy and XOR-decode a working buffer
    let mut buf = frame.to_vec();
    let xor_key = [buf[0], buf[1], buf[2], buf[3]];
    if buf.len() > 4 { xor_bytes(xor_key, &mut buf[4..]); }

    let enc_flags = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
    let length_be = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
    let typ_be = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);

    let payload_len = length_be.saturating_sub(8) as usize;
    if 32 + payload_len > buf.len() { return Err("length mismatch"); }
    let payload = &buf[32 .. 32 + payload_len];

    let plain = if enc_flags == ENC_FLAG_AES256 {
        let key = aes_key.ok_or("missing aes key")?;
        if payload.len() < 16 { return Err("short iv"); }
        let iv = &payload[..16];
        let ct = &payload[16..];
        let dec = Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| "bad key/iv")?;
        dec.decrypt_padded_vec_mut::<Pkcs7>(ct).map_err(|_| "decrypt")?
    } else {
        payload.to_vec()
    };

    let (tlvs, _used) = mp_unpack_tlvs(&plain).map_err(|_| "tlv decode")?;

    let mut guid = [0u8; 16];
    guid.copy_from_slice(&buf[4..20]);
    let header = MpHeader { xor_key, session_guid: guid, enc_flags, length: length_be, typ: typ_be };
    Ok((header, tlvs))
}

pub fn peek_session_guid(frame: &[u8]) -> Option<[u8; 16]> {
    if frame.len() < 20 {
        return None;
    }
    let xor_key = [frame[0], frame[1], frame[2], frame[3]];
    let mut guid = [0u8; 16];
    for (i, b) in guid.iter_mut().enumerate() {
        *b = frame[4 + i] ^ xor_key[(4 + i) % 4];
    }
    Some(guid)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpSessState {
    pub aes_key: Option<[u8; 32]>,
    pub enabled: bool,
}
