use std::vec::Vec;

use core_defs::packer::{mp_pack_tlvs, mp_unpack_tlvs, MpTlv};
use get_proc::{CastFunc, GetModuleHandle, GetProcAddress};
use rand::RngCore;

pub const ENC_FLAG_NONE: u32 = 0x0;
pub const ENC_FLAG_AES256: u32 = 0x1;

const AES_BLOCK: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpHeader {
    pub xor_key: [u8; 4],
    pub session_guid: [u8; 16],
    pub enc_flags: u32,
    pub length: u32,
    pub typ: u32,
}

type HCRYPTPROV = usize;
type HCRYPTKEY = usize;

type CryptAcquireContextWFn = extern "system" fn(*mut HCRYPTPROV, *const u16, *const u16, u32, u32) -> i32;
type CryptReleaseContextFn = extern "system" fn(HCRYPTPROV, u32) -> i32;
type CryptGenRandomFn = extern "system" fn(HCRYPTPROV, u32, *mut u8) -> i32;
type CryptImportKeyFn = extern "system" fn(HCRYPTPROV, *const u8, u32, HCRYPTKEY, u32, *mut HCRYPTKEY) -> i32;
type CryptSetKeyParamFn = extern "system" fn(HCRYPTKEY, u32, *const u8, u32) -> i32;
type CryptEncryptFn = extern "system" fn(HCRYPTKEY, usize, i32, u32, *mut u8, *mut u32, u32) -> i32;
type CryptDecryptFn = extern "system" fn(HCRYPTKEY, usize, i32, u32, *mut u8, *mut u32) -> i32;
type CryptDestroyKeyFn = extern "system" fn(HCRYPTKEY) -> i32;

const PROV_RSA_AES: u32 = 24;
const CRYPT_VERIFYCONTEXT: u32 = 0xF000_0000;

const PLAINTEXTKEYBLOB: u8 = 0x08;
const CUR_BLOB_VERSION: u8 = 0x02;
const CALG_AES_256: u32 = 0x0000_6610;

const KP_MODE: u32 = 4;
const KP_IV: u32 = 1;
const CRYPT_MODE_CBC: u32 = 1;

#[repr(C)]
struct BLOBHEADER {
    b_type: u8,
    b_version: u8,
    reserved: u16,
    ai_key_alg: u32,
}

#[repr(C)]
struct Aes256KeyBlob {
    header: BLOBHEADER,
    length: u32,
    key: [u8; 32],
}

#[derive(Clone, Copy)]
struct Advapi32 {
    acquire: CryptAcquireContextWFn,
    release: CryptReleaseContextFn,
    gen_random: CryptGenRandomFn,
    import_key: CryptImportKeyFn,
    set_key_param: CryptSetKeyParamFn,
    encrypt: CryptEncryptFn,
    decrypt: CryptDecryptFn,
    destroy_key: CryptDestroyKeyFn,
}

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

fn xor_bytes(xk: [u8; 4], data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= xk[i % 4];
    }
}

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

fn aes_encrypt_cbc_pkcs7(adv: Advapi32, aes_key: &[u8; 32], plain: &[u8]) -> Option<Vec<u8>> {
    let prov = acquire_provider(adv)?;
    let key = import_aes_key(adv, prov, aes_key)?;

    let block = AES_BLOCK;

    let mode = CRYPT_MODE_CBC.to_le_bytes();
    let _ = (adv.set_key_param)(key, KP_MODE, mode.as_ptr(), 0);

    let mut iv = vec![0u8; block];
    let ok_rng = (adv.gen_random)(prov, iv.len() as u32, iv.as_mut_ptr());
    if ok_rng == 0 {
        rand::thread_rng().fill_bytes(&mut iv);
    }
    let _ = (adv.set_key_param)(key, KP_IV, iv.as_ptr(), 0);

    let max = (plain.len() + block) as u32;
    let mut buf = plain.to_vec();
    buf.resize(max as usize, 0u8);
    let mut len: u32 = plain.len() as u32;

    let ok_enc = (adv.encrypt)(key, 0, 1, 0, buf.as_mut_ptr(), &mut len as *mut u32, max);

    let _ = (adv.destroy_key)(key);
    let _ = (adv.release)(prov, 0);

    if ok_enc == 0 {
        return None;
    }

    buf.truncate(len as usize);

    let mut out = Vec::with_capacity(iv.len() + buf.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&buf);
    Some(out)
}

fn aes_decrypt_cbc_pkcs7(adv: Advapi32, aes_key: &[u8; 32], payload: &[u8]) -> Option<Vec<u8>> {
    let prov = acquire_provider(adv)?;
    let key = import_aes_key(adv, prov, aes_key)?;

    let block = AES_BLOCK;
    if payload.len() < block {
        let _ = (adv.destroy_key)(key);
        let _ = (adv.release)(prov, 0);
        return None;
    }

    let iv = &payload[..block];
    let ct = &payload[block..];

    let mode = CRYPT_MODE_CBC.to_le_bytes();
    let _ = (adv.set_key_param)(key, KP_MODE, mode.as_ptr(), 0);
    let _ = (adv.set_key_param)(key, KP_IV, iv.as_ptr(), 0);

    let mut buf = ct.to_vec();
    let mut len: u32 = buf.len() as u32;
    let ok_dec = (adv.decrypt)(key, 0, 1, 0, buf.as_mut_ptr(), &mut len as *mut u32);

    let _ = (adv.destroy_key)(key);
    let _ = (adv.release)(prov, 0);

    if ok_dec == 0 {
        return None;
    }

    buf.truncate(len as usize);
    Some(buf)
}

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
