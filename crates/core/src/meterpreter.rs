//! # Meterpreter Frame Protocol
//!
//! Este módulo implementa el protocolo de framing y encriptación usado para
//! comunicación segura entre agentes y servidores C2.
//!
//! ## Estructura del Frame
//!
//! Cada frame tiene la siguiente estructura:
//!
//! ```text
//! +----------+---------------+-----------+----------+----------+------------+
//! | XOR Key  | Session GUID  | Enc Flags | Length   | Type     | Payload    |
//! | 4 bytes  | 16 bytes      | 4 bytes   | 4 bytes  | 4 bytes  | N bytes    |
//! +----------+---------------+-----------+----------+----------+------------+
//! ```
//!
//! ### Campos del Header (32 bytes total)
//!
//! | Offset | Campo | Descripción |
//! |--------|-------|-------------|
//! | 0-3 | XOR Key | Clave de 4 bytes para ofuscación simple |
//! | 4-19 | Session GUID | Identificador único de sesión |
//! | 20-23 | Enc Flags | Flags de encriptación (0=sin, 1=AES-256) |
//! | 24-27 | Length | Longitud del payload + 8 (big-endian) |
//! | 28-31 | Type | Tipo de paquete (big-endian) |
//!
//! ### Ofuscación XOR
//!
//! Todos los bytes después del XOR Key (offset 4+) están ofuscados con XOR
//! usando la clave de 4 bytes de forma cíclica:
//!
//! ```text
//! out[i] = data[i] ^ xor_key[i % 4]
//! ```
//!
//! Esto proporciona una capa simple de ofuscación para evadir detección
//! básica de strings, aunque NO es encriptación real.
//!
//! ### Encriptación AES-256-CBC
//!
//! Cuando `enc_flags = ENC_FLAG_AES256`:
//! 1. El payload contiene: IV (16 bytes) + Ciphertext
//! 2. AES-256-CBC con padding PKCS7
//! 3. La clave AES se negocia previamente con el comando NEGOTIATE_TLV_ENCRYPTION
//!
//! ## Flujo de Comunicación
//!
//! ```text
//! Agente                              Servidor
//!   |                                    |
//!   |-- Checkin (sin encriptar) -------->|
//!   |<--- NEGOTIATE_KEY request ---------|
//!   |---- AES key response ------------->|
//!   |                                    |
//!   |-- Comandos (AES encriptado) ------>|
//!   |<--- Resultados (AES encriptado) ---|
//! ```

use std::vec::Vec;
use rand::RngCore;
use cipher::{KeyIvInit, block_padding::Pkcs7, BlockEncryptMut, BlockDecryptMut};
use aes::Aes256;
use cbc::{Encryptor, Decryptor};

use crate::packer::{MpTlv, mp_pack_tlvs, mp_unpack_tlvs};

/// Sin encriptación - payload en texto plano (solo XOR ofuscation).
pub const ENC_FLAG_NONE: u32 = 0x0;

/// Encriptación AES-256-CBC activa.
/// El payload contiene IV (16 bytes) + ciphertext.
pub const ENC_FLAG_AES256: u32 = 0x1;

/// Representa el header parseado de un frame Meterpreter.
///
/// Este struct se usa para acceder a los campos del header después
/// de decodificar el frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpHeader {
    /// Clave XOR usada para ofuscación (se envía sin ofuscar).
    pub xor_key: [u8; 4],
    /// Identificador único de la sesión (GUID de 128 bits).
    pub session_guid: [u8; 16],
    /// Flags de encriptación: ENC_FLAG_NONE o ENC_FLAG_AES256.
    pub enc_flags: u32,
    /// Longitud del payload + 8 bytes (big-endian en wire).
    pub length: u32,
    /// Tipo de paquete (big-endian en wire).
    pub typ: u32,
}

/// Aplica ofuscación XOR a un slice de bytes.
///
/// La ofuscación XOR es reversible: aplicar dos veces restaura el original.
/// Se usa para ofuscar el header y payload, evitando detección de strings.
///
/// ## Argumentos
///
/// - `xk`: Clave XOR de 4 bytes
/// - `data`: Bytes a ofuscar (se modifica in-place)
fn xor_bytes(xk: [u8; 4], data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() { *b ^= xk[i % 4]; }
}

/// Codifica TLVs en un frame Meterpreter completo.
///
/// ## Proceso
///
/// 1. Serializa los TLVs a bytes con `mp_pack_tlvs`
/// 2. Si hay clave AES:
///    - Genera IV aleatorio de 16 bytes
///    - Encripta con AES-256-CBC + PKCS7 padding
///    - Prepende IV al ciphertext
/// 3. Construye header de 32 bytes:
///    - XOR key aleatorio
///    - Session GUID
///    - Enc flags (0 o 1)
///    - Length (payload.len() + 8)
///    - Type
/// 4. Aplica XOR ofuscación a todo excepto los primeros 4 bytes
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
/// Frame completo listo para enviar por el transporte.
pub fn encode_frame(session_guid: [u8; 16], pkt_type: u32, tlvs: &[MpTlv], aes_key: Option<&[u8; 32]>) -> Vec<u8> {
    // Build TLV payload in classic BE format
    let mut payload = mp_pack_tlvs(tlvs);

    let mut enc_flags = ENC_FLAG_NONE;
    if let Some(key) = aes_key {
        // AES-256-CBC with PKCS7, prepend IV
        // Generar IV aleatorio - cada mensaje usa IV único para seguridad
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let enc = Encryptor::<Aes256>::new_from_slices(key, &iv).expect("bad key/iv");
        let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(&payload);
        // Prepend IV al ciphertext: [IV 16 bytes][Ciphertext N bytes]
        let mut with_iv = Vec::with_capacity(16 + ct.len());
        with_iv.extend_from_slice(&iv);
        with_iv.extend_from_slice(&ct);
        payload = with_iv;
        enc_flags = ENC_FLAG_AES256;
    }

    // Header.length includes sizeof(TlvHeader) (8) + payload bytes (IV+ciphertext or plaintext)
    let length_field: u32 = 8u32 + (payload.len() as u32);

    let mut header = [0u8; 32];
    // xor_key - clave aleatoria para ofuscación simple
    let xor_key = {
        let x = rand::random::<u32>();
        x.to_le_bytes()
    };
    header[0..4].copy_from_slice(&xor_key);
    // session_guid - identificador de sesión
    header[4..20].copy_from_slice(&session_guid);
    // enc_flags, length, typ (BE) - todos en big-endian
    header[20..24].copy_from_slice(&enc_flags.to_be_bytes());
    header[24..28].copy_from_slice(&length_field.to_be_bytes());
    header[28..32].copy_from_slice(&pkt_type.to_be_bytes());

    // Build full buffer then XOR tail (skip xor_key itself)
    // El XOR key NO se ofusca, solo los bytes posteriores
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&payload);
    xor_bytes(xor_key, &mut out[4..]);
    out
}

/// Decodifica un frame Meterpreter a header y TLVs.
///
/// ## Proceso
///
/// 1. Extrae XOR key de los primeros 4 bytes
/// 2. Des-ofusca el resto del frame con XOR
/// 3. Parsea header: enc_flags, length, type
/// 4. Si enc_flags == AES256:
///    - Extrae IV de los primeros 16 bytes del payload
///    - Desencripta el resto con AES-256-CBC
/// 5. Deserializa TLVs del payload (encriptado o no)
///
/// ## Argumentos
///
/// - `frame`: Frame completo recibido del transporte
/// - `aes_key`: Clave AES opcional (requerida si enc_flags == AES256)
///
/// ## Retorna
///
/// - `Ok((MpHeader, Vec<MpTlv>))`: Header parseado y TLVs
/// - `Err(&'static str)`: Error de parsing o desencriptación
///
/// ## Errores
///
/// - "short frame": Frame menor a 32 bytes
/// - "length mismatch": Longitud declarada no coincide con buffer
/// - "missing aes key": Frame encriptado pero no se proporcionó clave
/// - "short iv": Payload encriptado menor a 16 bytes
/// - "decrypt": Error de desencriptación
/// - "tlv decode": Error parseando TLVs
pub fn decode_frame(frame: &[u8], aes_key: Option<&[u8; 32]>) -> Result<(MpHeader, Vec<MpTlv>), &'static str> {
    if frame.len() < 32 { return Err("short frame"); }
    // Copy and XOR-decode a working buffer
    // Necesitamos copiar porque XOR modifica in-place
    let mut buf = frame.to_vec();
    let xor_key = [buf[0], buf[1], buf[2], buf[3]];
    if buf.len() > 4 { xor_bytes(xor_key, &mut buf[4..]); }

    // Parsear campos del header (big-endian)
    let enc_flags = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
    let length_be = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
    let typ_be = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);

    // Length incluye 8 bytes extra del "TlvHeader" virtual
    let payload_len = length_be.saturating_sub(8) as usize;
    if 32 + payload_len > buf.len() { return Err("length mismatch"); }
    let payload = &buf[32 .. 32 + payload_len];

    // Desencriptar si es necesario
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

    // Deserializar TLVs
    let (tlvs, _used) = mp_unpack_tlvs(&plain).map_err(|_| "tlv decode")?;

    // Construir header para retornar
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&buf[4..20]);
    let header = MpHeader { xor_key, session_guid: guid, enc_flags, length: length_be, typ: typ_be };
    Ok((header, tlvs))
}

/// Extrae el Session GUID de un frame sin decodificar completamente.
///
/// Esta función es útil para routing de sesiones cuando se reciben
/// múltiples conexiones de diferentes agentes.
///
/// ## Argumentos
///
/// - `frame`: Frame completo (mínimo 20 bytes)
///
/// ## Retorna
///
/// - `Some([u8; 16])`: Session GUID extraído
/// - `None`: Frame muy corto
///
/// ## Uso típico
///
/// ```rust
/// // En el servidor, para routing de sesiones:
/// if let Some(guid) = peek_session_guid(&incoming_frame) {
///     let session = sessions.get(&guid);
///     // Procesar frame con la sesión correcta
/// }
/// ```
pub fn peek_session_guid(frame: &[u8]) -> Option<[u8; 16]> {
    if frame.len() < 20 {
        return None;
    }
    let xor_key = [frame[0], frame[1], frame[2], frame[3]];
    let mut guid = [0u8; 16];
    // Des-ofuscar solo el GUID sin procesar el resto
    for (i, b) in guid.iter_mut().enumerate() {
        *b = frame[4 + i] ^ xor_key[(4 + i) % 4];
    }
    Some(guid)
}

/// Estado de encriptación de una sesión.
///
/// Se usa para trackear si la sesión ya negoció clave AES.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpSessState {
    /// Clave AES negociada (None si no hay encriptación).
    pub aes_key: Option<[u8; 32]>,
    /// Si la encriptación está activa para esta sesión.
    pub enabled: bool,
}
