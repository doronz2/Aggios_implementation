// Library wrapper for the existing EPA benchmark crate.
//
// This file only re-exports the existing modules so that the EPA prover and
// verifier can be used as a black box from other crates (the Aggios layer).
// It contains no cryptographic logic and does not modify the EPA protocol.

pub mod fast_div;
pub mod kzg_helpers;
pub mod prover;
pub mod structs;
pub mod utils;
pub mod verifier;
