//! Aggios demo server and benchmark CLI.
//!
//! Subcommands:
//!   serve            -- run the HTTP API + /aggios UI
//!   benchmark        -- run one benchmark configuration
//!   benchmark-suite  -- run a series of voter counts

mod routes;
mod state;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use aggios_core::benchmark::{
    result_to_csv, run_benchmark_catching, AssignmentStrategy, BenchmarkConfig,
    VoteDistributionKind,
};
use aggios_core::election::ElectionTemplate;

#[derive(Parser)]
#[command(name = "aggios-server", about = "Basic Aggios demo (EPA used as a black box)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, ValueEnum)]
enum TemplateArg {
    Representative,
    CrimeReform,
}

impl From<TemplateArg> for ElectionTemplate {
    fn from(t: TemplateArg) -> Self {
        match t {
            TemplateArg::Representative => ElectionTemplate::Representative,
            TemplateArg::CrimeReform => ElectionTemplate::CrimeReform,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum AssignmentArg {
    RoundRobin,
    Uniform,
    Weighted,
    Skewed,
}

impl From<AssignmentArg> for AssignmentStrategy {
    fn from(a: AssignmentArg) -> Self {
        match a {
            AssignmentArg::RoundRobin => AssignmentStrategy::RoundRobin,
            AssignmentArg::Uniform => AssignmentStrategy::Uniform,
            AssignmentArg::Weighted => AssignmentStrategy::Weighted,
            AssignmentArg::Skewed => AssignmentStrategy::Skewed,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum VoteDistArg {
    Uniform,
    Fixed,
    Skewed,
}

impl From<VoteDistArg> for VoteDistributionKind {
    fn from(v: VoteDistArg) -> Self {
        match v {
            VoteDistArg::Uniform => VoteDistributionKind::Uniform,
            VoteDistArg::Fixed => VoteDistributionKind::Fixed,
            VoteDistArg::Skewed => VoteDistributionKind::Skewed,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP API and the /aggios UI.
    Serve {
        #[arg(long, default_value = "8787")]
        port: u16,
    },
    /// Run one benchmark configuration.
    Benchmark {
        #[arg(long)]
        voters: usize,
        #[arg(long, default_value = "3")]
        aggregators: usize,
        #[arg(long, value_enum, default_value = "representative")]
        template: TemplateArg,
        #[arg(long, value_enum, default_value = "uniform")]
        assignment: AssignmentArg,
        #[arg(long, value_enum, default_value = "uniform")]
        vote_distribution: VoteDistArg,
        #[arg(long, default_value = "42")]
        seed: u64,
        /// true = full cryptography; false = counting-only simulation
        /// (clearly labeled NON-CRYPTOGRAPHIC in the output).
        #[arg(long, default_value = "true")]
        real_crypto: std::primitive::bool,
        #[arg(long, default_value = "false")]
        receipts: std::primitive::bool,
        /// Output JSON path (a .csv is written next to it too).
        #[arg(long)]
        out: PathBuf,
    },
    /// Run a suite of benchmarks over several voter counts.
    BenchmarkSuite {
        /// Comma-separated voter counts, e.g. 100,1000,10000,100000,1000000
        #[arg(long, value_delimiter = ',')]
        voters: Vec<usize>,
        #[arg(long, default_value = "3")]
        aggregators: usize,
        #[arg(long, value_enum, default_value = "representative")]
        template: TemplateArg,
        #[arg(long, default_value = "42")]
        seed: u64,
        #[arg(long, default_value = "true")]
        real_crypto: std::primitive::bool,
        /// Output directory.
        #[arg(long)]
        out: PathBuf,
    },
}

fn run_one_benchmark(config: &BenchmarkConfig, json_path: &PathBuf) -> bool {
    eprintln!(
        "== benchmark: {} voters, {} aggregators, seed {}, mode {} ==",
        config.voters,
        config.aggregators,
        config.seed,
        if config.real_crypto {
            "real-crypto"
        } else {
            "simulation (NON-CRYPTOGRAPHIC)"
        }
    );
    let cancel = AtomicBool::new(false);
    let result = run_benchmark_catching(
        config,
        &|e| {
            eprintln!(
                "[{}] {}{}",
                e.stage,
                e.aggregator
                    .as_deref()
                    .map(|a| format!("{}: ", a))
                    .unwrap_or_default(),
                e.message
            );
        },
        &cancel,
    );

    if let Some(dir) = json_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(json_path, serde_json::to_string_pretty(&result).unwrap())
        .expect("write results json");
    let csv_path = json_path.with_extension("csv");
    std::fs::write(&csv_path, result_to_csv(&result)).expect("write results csv");

    eprintln!(
        "success={} total={}ms proving={}ms verification={}ms proof_bytes={} rss={:?}",
        result.success,
        result.total_ms,
        result.epa_proving_time_ms,
        result.epa_verification_time_ms,
        result.proof_size_bytes_total,
        result.max_rss_bytes
    );
    if let Some(err) = &result.error {
        eprintln!("recorded failure: {}", err);
    }
    eprintln!("results: {} and {}", json_path.display(), csv_path.display());
    result.success
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve { port: 8787 }) {
        Command::Serve { port } => {
            let state = Arc::new(state::AppState::default());
            let app = routes::router(state).layer(
                tower_http::cors::CorsLayer::new()
                    .allow_origin(tower_http::cors::Any)
                    .allow_methods(tower_http::cors::Any)
                    .allow_headers(tower_http::cors::Any),
            );
            let addr = format!("0.0.0.0:{}", port);
            println!("Aggios demo listening on http://localhost:{}/aggios", port);
            let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
            axum::serve(listener, app).await.expect("server");
        }
        Command::Benchmark {
            voters,
            aggregators,
            template,
            assignment,
            vote_distribution,
            seed,
            real_crypto,
            receipts,
            out,
        } => {
            let config = BenchmarkConfig {
                voters,
                aggregators,
                template: template.into(),
                assignment: assignment.into(),
                vote_distribution: vote_distribution.into(),
                seed,
                real_crypto,
                receipts,
                ..Default::default()
            };
            let ok = tokio::task::spawn_blocking(move || run_one_benchmark(&config, &out))
                .await
                .unwrap();
            if !ok {
                std::process::exit(1);
            }
        }
        Command::BenchmarkSuite {
            voters,
            aggregators,
            template,
            seed,
            real_crypto,
            out,
        } => {
            let ok = tokio::task::spawn_blocking(move || {
                let mut all_ok = true;
                for count in &voters {
                    let config = BenchmarkConfig {
                        voters: *count,
                        aggregators,
                        template: template.into(),
                        seed,
                        real_crypto,
                        ..Default::default()
                    };
                    let json_path = out.join(format!("bench-{}.json", count));
                    // Honest recording: a failed size does not stop the suite,
                    // its failure reason is stored in its own results file.
                    all_ok &= run_one_benchmark(&config, &json_path);
                }
                all_ok
            })
            .await
            .unwrap();
            if !ok {
                std::process::exit(1);
            }
        }
    }
}
