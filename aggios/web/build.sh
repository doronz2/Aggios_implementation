#!/usr/bin/env bash
# Build the fully static, in-browser Aggios demo (WASM) into a deployable
# directory. Usage: web/build.sh [output-dir]   (default: web/dist)
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-web/dist}"

echo "==> building aggios-wasm (wasm32-wasip1, release)"
cargo build --release --target wasm32-wasip1 -p aggios-wasm

echo "==> assembling static bundle in $OUT"
mkdir -p "$OUT"
cp crates/aggios-server/static/index.html "$OUT/"
cp crates/aggios-server/static/style.css "$OUT/"
cp crates/aggios-server/static/app.js "$OUT/"
cp web/boot.js web/worker.js "$OUT/"
cp target/wasm32-wasip1/release/aggios_wasm.wasm "$OUT/aggios.wasm"

echo "==> done: $(du -sh "$OUT" | cut -f1) in $OUT"
