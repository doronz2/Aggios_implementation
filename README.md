# Aggios — Basic Aggios demo on top of the existing EPA implementation

This repository contains a full **basic Aggios** prototype (aggregator-based proxy
voting) built **around** the existing EPA (proof-of-partition) implementation from
[`mariuslp/aggios_epa_benchmark`](https://github.com/mariuslp/aggios_epa_benchmark),
plus a demo web UI served at `/aggios` (for doronzarchy.com).

> **EPA is used as an existing black box.** The EPA prover/verifier equations in
> `aggios_epa_benchmark/` were **not** reimplemented or modified. The only change to
> that directory is a 12-line `src/lib.rs` that re-exports its existing modules so it
> can be linked as a library. Everything Aggios-specific lives in `aggios/` and calls
> EPA through an adapter (`aggios/crates/aggios-core/src/epa_adapter.rs`).

## Layout

**Live demo:** <https://doronzarchy.com/aggios/> — the page runs fully in the
browser: aggios-core *and* the black-box EPA prover/verifier are compiled to
WebAssembly (`wasm32-wasip1`) and executed in a web worker, so the static site
needs no backend. The deployed bundle is built from this repository with
`aggios/web/build.sh`, so the demo exercises the complete implementation —
the same code the native server, tests, and benchmark CLI use.

`aggios_epa_benchmark/` is vendored from
[`mariuslp/aggios_epa_benchmark`](https://github.com/mariuslp/aggios_epa_benchmark)
at commit `697ba51` (see `aggios_epa_benchmark/VENDORED.md`); the only local
addition is the 12-line `src/lib.rs` re-export.

```
aggios_epa_benchmark/        existing EPA implementation (black box, + minimal lib.rs)
aggios/                      the Aggios prototype (Rust workspace)
  crates/aggios-core/        all cryptography outside EPA
    src/hash.rs                domain-separated hash_to_fr / hash_to_G1
    src/bls.rs                 BLS delegation signatures (individual + aggregate)
    src/eqlog.rs               cross-group equal-log proof for registration tokens
    src/labels.rs              candidate / NO_VOTE / PAD scalar labels
    src/domain.rs              Lagrange-basis KZG commitments (group IFFT), pad scalars
    src/registration.rs        registration tokens, finalization, validator checks
    src/tally.rs               tally witness construction, validator flow, global tally
    src/epa_adapter.rs         black-box wrapper: SRS, prove, verify, proof serialization
    src/artifacts.rs           canonical JSON bulletin-board artifacts
    src/benchmark.rs           benchmark engine (real-crypto and simulation modes)
    src/demo.rs                host-independent demo election state machine
    tests/aggios_tests.rs      integration tests
  crates/aggios-server/      axum backend API + benchmark CLI + embedded /aggios UI
    static/                    the /aggios single-page UI (shared with the WASM build)
  crates/aggios-wasm/        wasm32-wasip1 build for the static website
  web/                       WASI shim, web worker, and build script for the static bundle
```

## What is implemented

- **Basic Aggios**: each voter delegates to exactly one aggregator (A1/A2/A3 by
  default); aggregators publish tallies with EPA proofs; validators verify; the final
  tally sums only verified aggregators and excludes NO_VOTE and PAD partitions.
- **BLS delegation signatures**: `σ_i = sk_i · H_G1("AGGIOS_DELEGATION" || election_id
  || aggregator_id)`, verified individually and as an aggregate
  (`e(Σσ_i, g2) == e(H_M, Σpk_i)`).
- **Registration tokens**: after registration closes, voter `i` at local index `idx_i`
  gets `τ_i = skv_i · B_i` where `B_i` is the KZG commitment to the Lagrange basis
  polynomial of its slot; deterministic public padding tokens fill the domain to a
  power of two. Validators rebuild the committed vector as
  `C_commit = Σ τ_i + Σ τ_pad_p`.
- **EqLog registration proof**: a cross-group Chaum–Pedersen proof that `τ_i` (in G1)
  and the voting key `pkv_i` (in G2) use the same secret scalar `skv_i`, bound to
  election, aggregator, voter, index, and domain size.
- **EPA black-box tally proof**: aggregators build the tally witness (one partition per
  candidate + NO_VOTE + PAD) and call the existing EPA prover through the adapter;
  validators recompute all public inputs and call the existing EPA verifier.
- **Validator flow**: duplicate-voter checks across aggregators, BLS + EqLog +
  pad-token + `C_commit` recomputation checks, EPA verification, verified global tally.
- **Public bulletin board** with JSON export of every artifact.
- **UI** at `/aggios`: overview, admin, voter, aggregator dashboard,
  validator/bulletin board, and benchmark sections.
- **Benchmarks**: CLI and web UI, 10² … 10⁶ voters, round-robin/uniform/weighted/
  skewed-80/15/5 assignment, uniform/fixed/skewed vote distributions, seeded, with
  cancellation, streamed progress, and honest failure recording.

### Notes on the EPA adapter

Facts about the existing EPA implementation the adapter adapts to (documented in
`epa_adapter.rs`):

- BLS12-381 via arkworks 0.3; KZG10 SRS generated from `ark_std::test_rng()` — a
  **deterministic, demo-only trusted setup** which the adapter reproduces so provers
  and validators derive identical parameters.
- Domain sizes must be powers of two.
- EPA identifies partition labels by **domain-element index** (label scalar `ω^index`),
  not an arbitrary field element. The adapter maps partition position `j` to label
  index `j+1` canonically; the Aggios hash labels `w_j` are additionally published and
  recomputed by validators.
- The EPA `Proof` object has no serialization; the adapter adds a canonical compressed
  encoding (wrapper-level only).
- Empty partitions (candidates with zero votes) are deterministically filtered out on
  both the prove and verify side before calling EPA — a zero-size partition is the
  empty set and needs no proof; the remaining subsets still cover the whole domain.
- The proof's shape is validated before verification because the EPA verifier panics
  (out-of-bounds) on structurally malformed proofs; the adapter converts panics into
  a clean "invalid" verdict.

## What is NOT implemented

- Aggios-Split, VWF, ACE, vote dilution, coercion resistance
- Real blockchain deployment
- Production trusted setup (the SRS is derived from a fixed seed)
- EPA is used as a black box
  ([mariuslp/aggios_epa_benchmark](https://github.com/mariuslp/aggios_epa_benchmark));
  its internals are not implemented here
- Receipts of inclusion

## Running

Requires Rust (stable). All commands from `aggios/`:

```bash
cd aggios

# Backend + UI (frontend is embedded in the binary; no separate build step):
cargo run --release -- serve --port 8787
# then open http://localhost:8787/aggios

# Tests (unit + integration; includes the N=100 real-crypto benchmark):
cargo test --workspace

# Slower N=1000 test:
cargo test --workspace --release -- --ignored

# One benchmark:
cargo run --release -- benchmark \
  --voters 100000 --aggregators 3 --template representative \
  --assignment uniform --vote-distribution uniform --seed 42 \
  --real-crypto true --receipts false --out results/bench-100000.json

# Suite (writes results/bench-<n>.json and .csv per size):
cargo run --release -- benchmark-suite \
  --voters 100,1000,10000,100000,1000000 --aggregators 3 --seed 42 --out results/

# Static in-browser (WASM) bundle, as deployed to doronzarchy.com/aggios/:
rustup target add wasm32-wasip1
web/build.sh              # outputs web/dist/ — copy it to the website's /aggios/
```

### In-browser (WASM) build

`crates/aggios-wasm` compiles the entire stack, including the unmodified EPA
prover/verifier, to `wasm32-wasip1`. WASI supplies the clocks the EPA code's
internal timers use, stdout for its progress prints (routed to the browser
console), and randomness; a ~100-line WASI shim (`web/worker.js`) provides
those imports inside a web worker, and `web/boot.js` bridges the UI to the
worker. Differences from the native backend, reported honestly in the UI:
single-threaded execution (rayon falls back to sequential), benchmark runs
block until complete, and mid-run cancellation is unavailable.

### Using `/aggios`

1. **Admin tab** — create an election (Representative, Crime-reform, or custom
   options), then *Open registration*.
2. **Voter tab** — create demo voters, pick an aggregator per voter (or use
   auto-assign), register. Admin then *closes registration / opens voting*; voters
   pick a candidate and vote.
3. **Admin tab** — close voting, then *Finalize*, *Prove* (EPA), *Verify* per
   aggregator, or use the verify-everything button.
4. **Aggregators tab** — per-aggregator tallies, NO_VOTE/PAD counts, domain size,
   proof status, proving/verification times, proof size, proof JSON download.
5. **Validator tab** — election parameters, candidate labels, bulletin board, all
   validator checks, verified global tally, and the **public artifact JSON export**
   (also at `GET /api/aggios/elections/<id>/public-artifact.json`;
   the raw event log is at `GET .../bulletin-board`).
6. **Benchmark tab** — run 10²…10⁶ voters with assignment/vote-distribution/seed
   options, watch streamed progress, cancel, download JSON/CSV results.

Large real-crypto benchmarks (10⁵–10⁶) are attempted honestly and can take a long
time and a lot of memory; failures are recorded with their reason, never silently
downsampled. Simulation mode is clearly labeled **NON-CRYPTOGRAPHIC** and only counts
votes.

## Security caveats

This is a demonstration, not a production voting system:

- The KZG SRS and its G2 powers are generated from a **fixed seed** (matching the EPA
  benchmark's setup); a real deployment needs a proper trusted-setup ceremony.
- **In basic Aggios the selected aggregator learns each delegated vote** (proxy
  voting); only the public sees just tallies, commitments, and proofs.
- The demo backend simulates voters' wallets and the voter→aggregator private channel
  in one process; `skv` never appears on the bulletin board, but a real system needs
  authenticated private channels and client-side key custody.
- The hash-to-curve used for BLS is a simple try-and-increment construction and the
  code is not constant-time; none of this code has been audited.
