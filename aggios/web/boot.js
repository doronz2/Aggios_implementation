/* Static-site bootstrap: runs the Aggios demo fully in the browser.
 * All cryptography (aggios-core + the black-box EPA prover/verifier) executes
 * in a WebAssembly worker; there is no backend. */
"use strict";

window.AGGIOS_WASM = true;

(() => {
  const worker = new Worker(new URL("worker.js", document.currentScript.src));
  let nextId = 1;
  const pending = new Map();

  worker.onmessage = (e) => {
    if (e.data.type === "progress") {
      window.dispatchEvent(
        new CustomEvent("aggios-progress", { detail: e.data.payload }),
      );
      return;
    }
    if (e.data.type === "ready") {
      window.dispatchEvent(new CustomEvent("aggios-wasm-ready"));
      return;
    }
    const { id, response } = e.data;
    const resolve = pending.get(id);
    pending.delete(id);
    if (resolve) resolve(response);
  };

  worker.onerror = (e) => {
    console.error("Aggios WASM worker error:", e.message || e);
  };

  window.aggiosWasmCall = (method, path, body) =>
    new Promise((resolve) => {
      const id = nextId++;
      pending.set(id, resolve);
      worker.postMessage({ id, method, path, body });
    });
})();
