/* Web worker hosting the Aggios WASM build (wasm32-wasip1).
 *
 * The whole crypto stack — aggios-core and the black-box EPA prover/verifier —
 * runs inside this worker. The minimal WASI shim below provides exactly the
 * imports the module needs: clock (EPA's internal timers), randomness
 * (key generation, proof blinding), and stdout (EPA's progress prints, routed
 * to the browser console).
 */
"use strict";

let instance = null;
let memory = null;
const decoder = new TextDecoder();
const encoder = new TextEncoder();

const wasi = {
  random_get(ptr, len) {
    // crypto.getRandomValues caps at 64KiB per call
    const view = new Uint8Array(memory.buffer, ptr, len);
    for (let off = 0; off < len; off += 65536) {
      crypto.getRandomValues(view.subarray(off, Math.min(off + 65536, len)));
    }
    return 0;
  },
  environ_sizes_get(countPtr, sizePtr) {
    const dv = new DataView(memory.buffer);
    dv.setUint32(countPtr, 0, true);
    dv.setUint32(sizePtr, 0, true);
    return 0;
  },
  environ_get() {
    return 0;
  },
  clock_time_get(id, _precision, outPtr) {
    // 0 = realtime, 1 = monotonic; nanoseconds as u64
    const ns =
      id === 0
        ? BigInt(Date.now()) * 1000000n
        : BigInt(Math.round(performance.now() * 1e6));
    new DataView(memory.buffer).setBigUint64(outPtr, ns, true);
    return 0;
  },
  fd_write(fd, iovsPtr, iovsLen, nwrittenPtr) {
    const dv = new DataView(memory.buffer);
    let written = 0;
    let text = "";
    for (let i = 0; i < iovsLen; i++) {
      const ptr = dv.getUint32(iovsPtr + i * 8, true);
      const len = dv.getUint32(iovsPtr + i * 8 + 4, true);
      text += decoder.decode(new Uint8Array(memory.buffer, ptr, len));
      written += len;
    }
    if (text.trim().length) {
      (fd === 2 ? console.warn : console.log)("[wasm]", text.replace(/\n$/, ""));
    }
    const dv2 = new DataView(memory.buffer);
    dv2.setUint32(nwrittenPtr, written, true);
    return 0;
  },
  proc_exit(code) {
    throw new Error(`wasm module exited with code ${code}`);
  },
  sched_yield() {
    return 0;
  },
};

const imports = {
  wasi_snapshot_preview1: wasi,
  aggios: {
    host_progress(ptr, len) {
      const payload = JSON.parse(
        decoder.decode(new Uint8Array(memory.buffer, ptr, len)),
      );
      postMessage({ type: "progress", payload });
    },
  },
};

const ready = (async () => {
  const url = new URL("aggios.wasm", self.location.href);
  let result;
  try {
    result = await WebAssembly.instantiateStreaming(fetch(url), imports);
  } catch (_e) {
    // Fallback for servers with a wrong .wasm MIME type.
    const bytes = await (await fetch(url)).arrayBuffer();
    result = await WebAssembly.instantiate(bytes, imports);
  }
  instance = result.instance;
  memory = instance.exports.memory;
  postMessage({ type: "ready" });
})();

onmessage = async (e) => {
  const { id, method, path, body } = e.data;
  try {
    await ready;
    const req = encoder.encode(JSON.stringify({ method, path, body }));
    const ptr = instance.exports.aggios_alloc(req.length);
    new Uint8Array(memory.buffer, ptr, req.length).set(req);
    const len = instance.exports.aggios_handle(ptr, req.length);
    instance.exports.aggios_dealloc(ptr, req.length);
    const out = decoder.decode(
      new Uint8Array(memory.buffer, instance.exports.aggios_response_ptr(), len),
    );
    postMessage({ id, response: JSON.parse(out) });
  } catch (err) {
    postMessage({
      id,
      response: { status: 500, body: { error: `WASM error: ${err}` } },
    });
  }
};
