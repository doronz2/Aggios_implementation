//! HTTP API for the Aggios demo (spec section 15) plus the /aggios UI host.
//!
//! Election-flow logic lives in `aggios_core::demo` (shared with the WASM
//! build used on the static website); these handlers are thin wrappers.
//! Benchmark jobs run on OS threads and are managed here.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use aggios_core::benchmark::{result_to_csv, run_benchmark_catching, BenchmarkConfig};
use aggios_core::demo::{CreateElectionRequest, DemoError};

use crate::state::{now_ms, AppState, BenchJob, JobStatus};

type ApiResult<T> = Result<T, ApiError>;

pub struct ApiError(StatusCode, String);

impl ApiError {
    fn bad(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::BAD_REQUEST, msg.into())
    }
    fn not_found(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::NOT_FOUND, msg.into())
    }
    fn internal(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<DemoError> for ApiError {
    fn from(e: DemoError) -> Self {
        ApiError(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            e.message,
        )
    }
}

/// Run a (possibly slow, CPU-heavy) demo-state operation on the blocking
/// pool. The demo lock is held for the duration; fine for a demo server.
async fn with_demo<F>(state: Arc<AppState>, f: F) -> ApiResult<Json<Value>>
where
    F: FnOnce(&mut aggios_core::demo::DemoState) -> Result<Value, DemoError> + Send + 'static,
{
    let value = tokio::task::spawn_blocking(move || {
        let mut demo = state.demo.lock().unwrap();
        f(&mut demo)
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(Json(value))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::permanent("/aggios/") }))
        .route("/aggios", get(|| async { Redirect::permanent("/aggios/") }))
        .route("/aggios/", get(ui_index))
        .route("/aggios/boot.js", get(ui_boot))
        .route("/aggios/app.js", get(ui_js))
        .route("/aggios/style.css", get(ui_css))
        .route("/api/aggios/elections", post(create_election).get(list_elections))
        .route("/api/aggios/elections/:eid", get(get_election))
        .route("/api/aggios/elections/:eid/phase", post(set_phase))
        .route(
            "/api/aggios/elections/:eid/voters/demo-create",
            post(demo_create_voters),
        )
        .route("/api/aggios/elections/:eid/register", post(register_voter))
        .route("/api/aggios/elections/:eid/vote", post(cast_vote))
        .route(
            "/api/aggios/elections/:eid/voters/:vid/receipt",
            get(voter_receipt),
        )
        .route(
            "/api/aggios/elections/:eid/voters/:vid/verify-receipt",
            post(voter_receipt_post),
        )
        .route(
            "/api/aggios/elections/:eid/aggregators/:aid/finalize-registration",
            post(finalize_aggregator),
        )
        .route(
            "/api/aggios/elections/:eid/aggregators/:aid/prove",
            post(prove_aggregator),
        )
        .route(
            "/api/aggios/elections/:eid/aggregators/:aid/verify",
            post(verify_aggregator),
        )
        .route(
            "/api/aggios/elections/:eid/aggregators/:aid/proof.json",
            get(aggregator_proof_json),
        )
        .route("/api/aggios/elections/:eid/verify-all", post(verify_all))
        .route(
            "/api/aggios/elections/:eid/bulletin-board",
            get(bulletin_board),
        )
        .route(
            "/api/aggios/elections/:eid/public-artifact.json",
            get(public_artifact),
        )
        .route("/api/aggios/benchmarks", post(create_benchmark).get(list_benchmarks))
        .route("/api/aggios/benchmarks/:bid", get(get_benchmark))
        .route("/api/aggios/benchmarks/:bid/events", get(benchmark_events))
        .route(
            "/api/aggios/benchmarks/:bid/results.csv",
            get(benchmark_csv),
        )
        .route(
            "/api/aggios/benchmarks/:bid/results.json",
            get(benchmark_json),
        )
        .route("/api/aggios/benchmarks/:bid/cancel", post(cancel_benchmark))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// UI (embedded static files)
// ---------------------------------------------------------------------------

async fn ui_index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn ui_boot() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        "window.AGGIOS_WASM = false;\n",
    )
}

async fn ui_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        include_str!("../static/app.js"),
    )
}

async fn ui_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("../static/style.css"),
    )
}

// ---------------------------------------------------------------------------
// Elections (thin wrappers over aggios_core::demo)
// ---------------------------------------------------------------------------

async fn create_election(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateElectionRequest>,
) -> ApiResult<Json<Value>> {
    with_demo(state, move |demo| demo.create_election(req, now_ms())).await
}

async fn list_elections(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(state.demo.lock().unwrap().list_elections())
}

async fn get_election(
    State(state): State<Arc<AppState>>,
    Path(eid): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(state.demo.lock().unwrap().get_election(&eid)?))
}

#[derive(Deserialize)]
struct PhaseRequest {
    phase: String,
}

async fn set_phase(
    State(state): State<Arc<AppState>>,
    Path(eid): Path<String>,
    Json(req): Json<PhaseRequest>,
) -> ApiResult<Json<Value>> {
    with_demo(state, move |demo| demo.set_phase(&eid, &req.phase, now_ms())).await
}

#[derive(Deserialize)]
struct DemoCreateRequest {
    #[serde(default = "one")]
    count: usize,
}
fn one() -> usize {
    1
}

async fn demo_create_voters(
    State(state): State<Arc<AppState>>,
    Path(eid): Path<String>,
    Json(req): Json<DemoCreateRequest>,
) -> ApiResult<Json<Value>> {
    with_demo(state, move |demo| {
        demo.demo_create_voters(&eid, req.count, &mut rand::thread_rng())
    })
    .await
}

#[derive(Deserialize)]
struct RegisterRequest {
    voter_id: String,
    aggregator_id: String,
}

async fn register_voter(
    State(state): State<Arc<AppState>>,
    Path(eid): Path<String>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<Value>> {
    with_demo(state, move |demo| {
        demo.register_voter(&eid, &req.voter_id, &req.aggregator_id, now_ms())
    })
    .await
}

#[derive(Deserialize)]
struct VoteRequest {
    voter_id: String,
    candidate_id: String,
}

async fn cast_vote(
    State(state): State<Arc<AppState>>,
    Path(eid): Path<String>,
    Json(req): Json<VoteRequest>,
) -> ApiResult<Json<Value>> {
    with_demo(state, move |demo| {
        demo.cast_vote(&eid, &req.voter_id, &req.candidate_id)
    })
    .await
}

async fn voter_receipt(
    State(state): State<Arc<AppState>>,
    Path((eid, vid)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(Json(state.demo.lock().unwrap().voter_receipt(&eid, &vid)?))
}

async fn voter_receipt_post(
    State(state): State<Arc<AppState>>,
    Path((eid, vid)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(Json(state.demo.lock().unwrap().voter_receipt(&eid, &vid)?))
}

async fn finalize_aggregator(
    State(state): State<Arc<AppState>>,
    Path((eid, aid)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    with_demo(state, move |demo| {
        demo.finalize_aggregator(&eid, &aid, now_ms(), &mut rand::thread_rng())
    })
    .await
}

async fn prove_aggregator(
    State(state): State<Arc<AppState>>,
    Path((eid, aid)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    with_demo(state, move |demo| demo.prove_aggregator(&eid, &aid, now_ms())).await
}

async fn verify_aggregator(
    State(state): State<Arc<AppState>>,
    Path((eid, aid)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    with_demo(state, move |demo| demo.verify_aggregator(&eid, &aid, now_ms())).await
}

async fn aggregator_proof_json(
    State(state): State<Arc<AppState>>,
    Path((eid, aid)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state.demo.lock().unwrap().aggregator_proof_json(&eid, &aid)?,
    ))
}

async fn verify_all(
    State(state): State<Arc<AppState>>,
    Path(eid): Path<String>,
) -> ApiResult<Json<Value>> {
    with_demo(state, move |demo| demo.verify_all(&eid, now_ms())).await
}

async fn bulletin_board(
    State(state): State<Arc<AppState>>,
    Path(eid): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(state.demo.lock().unwrap().bulletin_board(&eid)?))
}

async fn public_artifact(
    State(state): State<Arc<AppState>>,
    Path(eid): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(state.demo.lock().unwrap().public_artifact(&eid)?))
}

// ---------------------------------------------------------------------------
// Benchmarks (OS-thread jobs)
// ---------------------------------------------------------------------------

async fn create_benchmark(
    State(state): State<Arc<AppState>>,
    Json(config): Json<BenchmarkConfig>,
) -> ApiResult<Json<Value>> {
    if config.voters > 10_000_000 {
        return Err(ApiError::bad("at most 10^7 voters"));
    }
    let id = state.next_id("bench");
    let job = Arc::new(BenchJob {
        id: id.clone(),
        config: config.clone(),
        created_unix_ms: now_ms(),
        status: std::sync::Mutex::new(JobStatus::Running),
        events: std::sync::Mutex::new(vec![]),
        result: std::sync::Mutex::new(None),
        cancel: std::sync::atomic::AtomicBool::new(false),
    });
    state
        .benchmarks
        .lock()
        .unwrap()
        .insert(id.clone(), job.clone());
    state.bench_order.lock().unwrap().push(id.clone());

    // Benchmarks run on a dedicated OS thread (they can take hours for 10^6).
    let thread_job = job.clone();
    std::thread::spawn(move || {
        let progress_job = thread_job.clone();
        let result = run_benchmark_catching(
            &thread_job.config,
            &move |e| progress_job.push_event(e),
            &thread_job.cancel,
        );
        let status = if result.success {
            JobStatus::Completed
        } else if thread_job.cancel.load(Ordering::Relaxed) {
            JobStatus::Cancelled
        } else {
            JobStatus::Failed
        };
        *thread_job.result.lock().unwrap() = Some(result);
        *thread_job.status.lock().unwrap() = status;
    });

    Ok(Json(json!({ "benchmark_id": id })))
}

async fn list_benchmarks(State(state): State<Arc<AppState>>) -> Json<Value> {
    let jobs = state.benchmarks.lock().unwrap();
    let order = state.bench_order.lock().unwrap();
    let list: Vec<Value> = order
        .iter()
        .rev()
        .filter_map(|id| jobs.get(id))
        .map(|job| job_summary(job))
        .collect();
    Json(json!({ "benchmarks": list }))
}

fn job_summary(job: &BenchJob) -> Value {
    json!({
        "benchmark_id": job.id,
        "config": job.config,
        "created_unix_ms": job.created_unix_ms,
        "status": *job.status.lock().unwrap(),
        "result": job.result.lock().unwrap().clone(),
    })
}

fn get_job(state: &AppState, bid: &str) -> ApiResult<Arc<BenchJob>> {
    state
        .benchmarks
        .lock()
        .unwrap()
        .get(bid)
        .cloned()
        .ok_or_else(|| ApiError::not_found("benchmark not found"))
}

async fn get_benchmark(
    State(state): State<Arc<AppState>>,
    Path(bid): Path<String>,
) -> ApiResult<Json<Value>> {
    let job = get_job(&state, &bid)?;
    Ok(Json(job_summary(&job)))
}

#[derive(Deserialize)]
struct EventsQuery {
    #[serde(default)]
    since: u64,
}

async fn benchmark_events(
    State(state): State<Arc<AppState>>,
    Path(bid): Path<String>,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<Value>> {
    let job = get_job(&state, &bid)?;
    let events = job.events.lock().unwrap();
    let new_events: Vec<_> = events
        .iter()
        .filter(|e| e.seq >= q.since)
        .cloned()
        .collect();
    Ok(Json(json!({
        "status": *job.status.lock().unwrap(),
        "events": new_events,
    })))
}

async fn benchmark_csv(
    State(state): State<Arc<AppState>>,
    Path(bid): Path<String>,
) -> ApiResult<Response> {
    let job = get_job(&state, &bid)?;
    let result = job.result.lock().unwrap();
    let result = result
        .as_ref()
        .ok_or_else(|| ApiError::bad("benchmark still running"))?;
    Ok((
        [(header::CONTENT_TYPE, "text/csv")],
        result_to_csv(result),
    )
        .into_response())
}

async fn benchmark_json(
    State(state): State<Arc<AppState>>,
    Path(bid): Path<String>,
) -> ApiResult<Json<Value>> {
    let job = get_job(&state, &bid)?;
    let result = job.result.lock().unwrap();
    let result = result
        .as_ref()
        .ok_or_else(|| ApiError::bad("benchmark still running"))?;
    Ok(Json(serde_json::to_value(result).unwrap()))
}

async fn cancel_benchmark(
    State(state): State<Arc<AppState>>,
    Path(bid): Path<String>,
) -> ApiResult<Json<Value>> {
    let job = get_job(&state, &bid)?;
    job.cancel.store(true, Ordering::Relaxed);
    Ok(Json(json!({ "cancelling": true })))
}
