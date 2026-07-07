//! Server-side state: the shared demo election state machine plus benchmark
//! job bookkeeping (jobs run on OS threads, so they live here and not in the
//! host-independent demo module).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Mutex;

use serde::Serialize;

use aggios_core::benchmark::{BenchmarkConfig, BenchmarkResult, ProgressEvent};
use aggios_core::demo::DemoState;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Serialize)]
pub struct TimedEvent {
    pub seq: u64,
    pub timestamp_unix_ms: u64,
    #[serde(flatten)]
    pub event: ProgressEvent,
}

pub struct BenchJob {
    pub id: String,
    pub config: BenchmarkConfig,
    pub created_unix_ms: u64,
    pub status: Mutex<JobStatus>,
    pub events: Mutex<Vec<TimedEvent>>,
    pub result: Mutex<Option<BenchmarkResult>>,
    pub cancel: AtomicBool,
}

impl BenchJob {
    pub fn push_event(&self, event: ProgressEvent) {
        let mut events = self.events.lock().unwrap();
        let seq = events.len() as u64;
        events.push(TimedEvent {
            seq,
            timestamp_unix_ms: now_ms(),
            event,
        });
    }
}

#[derive(Default)]
pub struct AppState {
    pub demo: Mutex<DemoState>,
    pub benchmarks: Mutex<HashMap<String, std::sync::Arc<BenchJob>>>,
    pub bench_order: Mutex<Vec<String>>,
    pub counter: AtomicU64,
}

impl AppState {
    pub fn next_id(&self, prefix: &str) -> String {
        let n = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{}-{}-{:04x}", prefix, now_ms() % 1_000_000, n)
    }
}
