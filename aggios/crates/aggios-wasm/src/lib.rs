//! WebAssembly (wasm32-wasip1) build of the basic Aggios demo.
//!
//! The whole crypto stack — aggios-core AND the black-box EPA
//! prover/verifier — runs inside the browser via a small WASI shim (WASI
//! supplies the clock the EPA code's timers need, stdout for its progress
//! prints, and randomness).
//!
//! Interface (called from the web worker):
//!   - `aggios_alloc(len) -> ptr` / `aggios_dealloc(ptr, len)`
//!   - `aggios_handle(ptr, len) -> response_len`: takes a JSON request
//!     `{method, path, body}` (path relative to /api/aggios) and stores a
//!     JSON response `{status, body}`; fetch it with `aggios_response_ptr()`.
//!   - benchmark progress is streamed through the `aggios.host_progress`
//!     import while `aggios_handle` runs.

use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use aggios_core::benchmark::{
    result_to_csv, run_benchmark_catching, BenchmarkConfig, ProgressEvent,
};
use aggios_core::demo::{CreateElectionRequest, DemoError, DemoState};

#[link(wasm_import_module = "aggios")]
extern "C" {
    fn host_progress(ptr: *const u8, len: usize);
}

fn emit_progress(event: &Value) {
    let bytes = event.to_string().into_bytes();
    unsafe { host_progress(bytes.as_ptr(), bytes.len()) };
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct BenchJob {
    id: String,
    config: BenchmarkConfig,
    created_unix_ms: u64,
    status: &'static str,
    events: Vec<Value>,
    result: Option<aggios_core::benchmark::BenchmarkResult>,
}

#[derive(Default)]
struct WasmApp {
    demo: DemoState,
    benches: Vec<BenchJob>,
}

fn app() -> &'static Mutex<WasmApp> {
    static APP: OnceLock<Mutex<WasmApp>> = OnceLock::new();
    APP.get_or_init(|| Mutex::new(WasmApp::default()))
}

fn response_buf() -> &'static Mutex<Vec<u8>> {
    static BUF: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
    BUF.get_or_init(|| Mutex::new(Vec::new()))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

type RouteResult = Result<Value, DemoError>;

fn parse_body<T: serde::de::DeserializeOwned>(body: &Value) -> Result<T, DemoError> {
    serde_json::from_value(body.clone())
        .map_err(|e| DemoError::bad(format!("invalid request body: {}", e)))
}

fn handle_benchmarks(app: &mut WasmApp, method: &str, segments: &[&str], body: &Value) -> RouteResult {
    match (method, segments) {
        ("POST", ["benchmarks"]) => {
            let config: BenchmarkConfig = parse_body(body)?;
            if config.voters > 10_000_000 {
                return Err(DemoError::bad("at most 10^7 voters"));
            }
            let id = format!("bench-{}-{:04x}", now_ms() % 1_000_000, app.benches.len());

            // The browser build is single-threaded: the benchmark runs
            // synchronously inside this call, streaming progress events to
            // the page through the host_progress import. Mid-run
            // cancellation is not possible in-browser.
            let events = Mutex::new(Vec::<Value>::new());
            let job_id = id.clone();
            let progress = |e: ProgressEvent| {
                let mut events = events.lock().unwrap();
                let timed = json!({
                    "seq": events.len() as u64,
                    "timestamp_unix_ms": now_ms(),
                    "stage": e.stage,
                    "message": e.message,
                    "aggregator": e.aggregator,
                    "fraction": e.fraction,
                });
                emit_progress(&json!({ "benchmark_id": job_id, "event": timed }));
                events.push(timed);
            };
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let result = run_benchmark_catching(&config, &progress, &cancel);

            let status = if result.success { "completed" } else { "failed" };
            app.benches.push(BenchJob {
                id: id.clone(),
                config,
                created_unix_ms: now_ms(),
                status,
                events: events.into_inner().unwrap(),
                result: Some(result),
            });
            Ok(json!({ "benchmark_id": id }))
        }
        ("GET", ["benchmarks"]) => Ok(json!({
            "benchmarks": app.benches.iter().rev().map(job_summary).collect::<Vec<_>>()
        })),
        ("GET", ["benchmarks", bid]) => {
            Ok(job_summary(find_job(app, bid)?))
        }
        ("GET", ["benchmarks", bid, "events"]) => {
            let job = find_job(app, bid)?;
            Ok(json!({ "status": job.status, "events": job.events }))
        }
        ("GET", ["benchmarks", bid, "results.json"]) => {
            let job = find_job(app, bid)?;
            match &job.result {
                Some(r) => Ok(serde_json::to_value(r).unwrap()),
                None => Err(DemoError::bad("benchmark still running")),
            }
        }
        ("GET", ["benchmarks", bid, "results.csv"]) => {
            let job = find_job(app, bid)?;
            match &job.result {
                Some(r) => Ok(json!({ "csv": result_to_csv(r) })),
                None => Err(DemoError::bad("benchmark still running")),
            }
        }
        ("POST", ["benchmarks", _bid, "cancel"]) => Ok(json!({
            "cancelling": false,
            "note": "cancellation is not available in the in-browser (single-threaded WASM) build",
        })),
        _ => Err(DemoError::not_found("no such route")),
    }
}

fn find_job<'a>(app: &'a WasmApp, bid: &str) -> Result<&'a BenchJob, DemoError> {
    app.benches
        .iter()
        .find(|j| j.id == bid)
        .ok_or_else(|| DemoError::not_found("benchmark not found"))
}

fn job_summary(job: &BenchJob) -> Value {
    json!({
        "benchmark_id": job.id,
        "config": job.config,
        "created_unix_ms": job.created_unix_ms,
        "status": job.status,
        "result": job.result,
    })
}

fn route(app: &mut WasmApp, method: &str, path: &str, body: &Value) -> RouteResult {
    let path = path.trim_start_matches("/api/aggios").trim_matches('/');
    // strip query string
    let path = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.first() == Some(&"benchmarks") {
        return handle_benchmarks(app, method, &segments, body);
    }

    let demo = &mut app.demo;
    let str_field = |body: &Value, key: &str| -> Result<String, DemoError> {
        body.get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| DemoError::bad(format!("missing field {}", key)))
    };

    match (method, segments.as_slice()) {
        ("POST", ["elections"]) => {
            let req: CreateElectionRequest = parse_body(body)?;
            demo.create_election(req, now_ms())
        }
        ("GET", ["elections"]) => Ok(demo.list_elections()),
        ("GET", ["elections", eid]) => demo.get_election(eid),
        ("POST", ["elections", eid, "phase"]) => {
            demo.set_phase(eid, &str_field(body, "phase")?, now_ms())
        }
        ("POST", ["elections", eid, "voters", "demo-create"]) => {
            let count = body.get("count").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
            demo.demo_create_voters(eid, count, &mut rand::thread_rng())
        }
        ("POST", ["elections", eid, "register"]) => demo.register_voter(
            eid,
            &str_field(body, "voter_id")?,
            &str_field(body, "aggregator_id")?,
            now_ms(),
        ),
        ("POST", ["elections", eid, "vote"]) => demo.cast_vote(
            eid,
            &str_field(body, "voter_id")?,
            &str_field(body, "candidate_id")?,
        ),
        ("GET", ["elections", eid, "voters", vid, "receipt"])
        | ("POST", ["elections", eid, "voters", vid, "verify-receipt"]) => {
            demo.voter_receipt(eid, vid)
        }
        ("POST", ["elections", eid, "aggregators", aid, "finalize-registration"]) => {
            demo.finalize_aggregator(eid, aid, now_ms(), &mut rand::thread_rng())
        }
        ("POST", ["elections", eid, "aggregators", aid, "prove"]) => {
            demo.prove_aggregator(eid, aid, now_ms())
        }
        ("POST", ["elections", eid, "aggregators", aid, "verify"]) => {
            demo.verify_aggregator(eid, aid, now_ms())
        }
        ("GET", ["elections", eid, "aggregators", aid, "proof.json"]) => {
            demo.aggregator_proof_json(eid, aid)
        }
        ("POST", ["elections", eid, "verify-all"]) => demo.verify_all(eid, now_ms()),
        ("GET", ["elections", eid, "bulletin-board"]) => demo.bulletin_board(eid),
        ("GET", ["elections", eid, "public-artifact.json"]) => demo.public_artifact(eid),
        _ => Err(DemoError::not_found(format!(
            "no such route: {} /{}",
            method, path
        ))),
    }
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

/// Allocate a buffer the host can write a request into.
#[no_mangle]
pub extern "C" fn aggios_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len.max(1));
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Free a buffer previously returned by `aggios_alloc`.
///
/// # Safety
/// `ptr`/`len` must come from a matching `aggios_alloc(len)` call.
#[no_mangle]
pub unsafe extern "C" fn aggios_dealloc(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
}

/// Handle one JSON request; returns the response length. The response bytes
/// are available at `aggios_response_ptr()` until the next call.
///
/// # Safety
/// `ptr`/`len` must describe a valid, initialized byte range.
#[no_mangle]
pub unsafe extern "C" fn aggios_handle(ptr: *const u8, len: usize) -> usize {
    let request_bytes = std::slice::from_raw_parts(ptr, len);
    let response = handle_request(request_bytes);
    let bytes = response.to_string().into_bytes();
    let mut buf = response_buf().lock().unwrap();
    *buf = bytes;
    buf.len()
}

#[no_mangle]
pub extern "C" fn aggios_response_ptr() -> *const u8 {
    response_buf().lock().unwrap().as_ptr()
}

fn handle_request(request_bytes: &[u8]) -> Value {
    let request: Value = match serde_json::from_slice(request_bytes) {
        Ok(v) => v,
        Err(e) => {
            return json!({ "status": 400, "body": { "error": format!("bad request json: {}", e) } })
        }
    };
    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
    let path = request.get("path").and_then(|v| v.as_str()).unwrap_or("/");
    let empty = json!({});
    let body = request.get("body").unwrap_or(&empty);

    let mut app = app().lock().unwrap();
    match route(&mut app, method, path, body) {
        Ok(value) => json!({ "status": 200, "body": value }),
        Err(e) => json!({ "status": e.status, "body": { "error": e.message } }),
    }
}
