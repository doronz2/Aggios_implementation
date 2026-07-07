//! aggios-core: all Aggios cryptography outside the black-box EPA proof.
//!
//! Layer map:
//! - [`hash`]        domain-separated hash_to_fr / hash_to_g1
//! - [`bls`]         BLS delegation signatures (individual + aggregate)
//! - [`eqlog`]       cross-group equal-discrete-log proof for registration tokens
//! - [`labels`]      candidate / NO_VOTE / PAD scalar labels
//! - [`domain`]      Lagrange basis commitments, padding scalars
//! - [`epa_adapter`] black-box wrapper around the existing EPA prover/verifier
//! - [`election`]    election parameters and templates
//! - [`registration`] registration flow: tokens, finalization, validation
//! - [`tally`]       tally witness construction and validator checks
//! - [`artifacts`]   canonical JSON artifacts for the public bulletin board
//! - [`benchmark`]   benchmark engine used by the CLI and the web UI

pub mod artifacts;
pub mod benchmark;
pub mod demo;
pub mod bls;
pub mod domain;
pub mod election;
pub mod epa_adapter;
pub mod eqlog;
pub mod error;
pub mod hash;
pub mod labels;
pub mod registration;
pub mod tally;

pub use error::{AggiosError, Result};
