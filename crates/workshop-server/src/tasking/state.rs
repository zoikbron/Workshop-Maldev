use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use tokio::sync::Mutex;

use core_defs::packer::MpTlv;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    next_session: u64,
    mp_sessions: HashMap<[u8; 16], MpSession>,
    active_guid: Option<[u8; 16]>,
    poll_mode: PollMode,
    metrics: Metrics,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    pub total_checkins: u64,
    pub total_results: u64,
    pub decode_failures: u64,
    pub tasks_queued: u64,
    pub tasks_delivered: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PollMode {
    Short,
    Long { timeout_ms: u64 },
}

struct MpSession {
    aes_key: Option<[u8; 32]>,
    enabled: bool,
    queued: VecDeque<Vec<MpTlv>>,
    outputs: VecDeque<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                next_session: 1,
                mp_sessions: HashMap::new(),
                active_guid: None,
                poll_mode: PollMode::Short,
                metrics: Metrics::default(),
            })),
        }
    }

    pub async fn metrics_snapshot(&self) -> Metrics {
        let g = self.inner.lock().await;
        g.metrics
    }

    pub async fn inc_checkins(&self) {
        let mut g = self.inner.lock().await;
        g.metrics.total_checkins += 1;
    }

    pub async fn inc_results(&self) {
        let mut g = self.inner.lock().await;
        g.metrics.total_results += 1;
    }

    pub async fn inc_decode_failures(&self) {
        let mut g = self.inner.lock().await;
        g.metrics.decode_failures += 1;
    }

    pub async fn inc_tasks_delivered(&self) {
        let mut g = self.inner.lock().await;
        g.metrics.tasks_delivered += 1;
    }

    pub async fn set_poll_mode_short(&self) {
        let mut g = self.inner.lock().await;
        g.poll_mode = PollMode::Short;
    }

    pub async fn set_poll_mode_long(&self, timeout_ms: u64) {
        let mut g = self.inner.lock().await;
        g.poll_mode = PollMode::Long { timeout_ms };
    }

    pub async fn poll_mode(&self) -> (bool, u64) {
        let g = self.inner.lock().await;
        match g.poll_mode {
            PollMode::Short => (false, 0),
            PollMode::Long { timeout_ms } => (true, timeout_ms),
        }
    }

    pub async fn register_mp_session(&self, guid: [u8; 16]) {
        let mut g = self.inner.lock().await;
        g.active_guid = Some(guid);
        g.mp_sessions.entry(guid).or_insert_with(|| MpSession {
            aes_key: None,
            enabled: false,
            queued: VecDeque::new(),
            outputs: VecDeque::new(),
        });
    }

    pub async fn set_active_guid(&self, guid: [u8; 16]) {
        let mut g = self.inner.lock().await;
        if g.mp_sessions.contains_key(&guid) {
            g.active_guid = Some(guid);
        }
    }

    pub async fn mp_list_sessions(&self) -> Vec<[u8; 16]> {
        let g = self.inner.lock().await;
        g.mp_sessions.keys().copied().collect()
    }

    pub async fn get_active_guid(&self) -> Option<[u8; 16]> {
        let g = self.inner.lock().await;
        g.active_guid
    }

    pub async fn mp_get_state(&self, guid: &[u8; 16]) -> Option<(bool, Option<[u8; 32]>)> {
        let g = self.inner.lock().await;
        let s = g.mp_sessions.get(guid)?;
        Some((s.enabled, s.aes_key))
    }

    pub async fn mp_set_aes_key(&self, guid: [u8; 16], key: [u8; 32]) {
        let mut g = self.inner.lock().await;
        if let Some(s) = g.mp_sessions.get_mut(&guid) {
            s.aes_key = Some(key);
            s.enabled = true;
        }
    }

    pub async fn mp_push_output(&self, guid: [u8; 16], text: String) {
        let mut g = self.inner.lock().await;
        let s = g.mp_sessions.entry(guid).or_insert_with(|| MpSession {
            aes_key: None,
            enabled: false,
            queued: VecDeque::new(),
            outputs: VecDeque::new(),
        });
        s.outputs.push_back(text);
        if s.outputs.len() > 50 {
            let _ = s.outputs.pop_front();
        }
    }

    pub async fn mp_take_outputs(&self, guid: [u8; 16]) -> Vec<String> {
        let mut g = self.inner.lock().await;
        let Some(s) = g.mp_sessions.get_mut(&guid) else {
            return Vec::new();
        };
        s.outputs.drain(..).collect()
    }

    pub async fn mp_take_next_task(&self, guid: &[u8; 16]) -> Option<Vec<MpTlv>> {
        let mut g = self.inner.lock().await;
        let s = g.mp_sessions.get_mut(guid)?;
        s.queued.pop_front()
    }

    pub async fn mp_queue_task(&self, guid: [u8; 16], tlvs: Vec<MpTlv>) {
        let mut g = self.inner.lock().await;
        let s = g.mp_sessions.entry(guid).or_insert_with(|| MpSession {
            aes_key: None,
            enabled: false,
            queued: VecDeque::new(),
            outputs: VecDeque::new(),
        });
        s.queued.push_back(tlvs);
        g.metrics.tasks_queued += 1;
    }

    pub async fn new_session_id(&self) -> u64 {
        let mut g = self.inner.lock().await;
        let id = g.next_session;
        g.next_session += 1;
        id
    }
}
