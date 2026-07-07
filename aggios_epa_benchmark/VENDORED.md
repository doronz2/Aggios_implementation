# Vendored from mariuslp/aggios_epa_benchmark

Upstream: https://github.com/mariuslp/aggios_epa_benchmark.git
Commit:   697ba51c06a34a267be00612ed48a8ce1d18d2db

This directory is the EPA (proof of partition) implementation for the paper
"Aggregator-Based Voting using Proof of Partition" (Lombard-Platet, Zarchy),
used by the Aggios layer in ../aggios strictly as a black box.

The ONLY local change relative to upstream is the addition of `src/lib.rs`,
a 12-line module re-export so the crate can be linked as a library. No
prover/verifier code was modified.
