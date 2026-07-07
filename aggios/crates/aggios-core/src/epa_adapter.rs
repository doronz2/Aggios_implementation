//! Adapter around the existing EPA implementation (black box).
//!
//! The EPA proof (see the paper "Aggregator-Based Voting using proof of
//! Partition") convinces a verifier that the committed vector behind
//! `commitment_c` is partitioned into disjoint subsets with public labels and
//! public sizes:
//!   - every domain index is included,
//!   - no index is included twice,
//!   - each claimed partition has the claimed size,
//!   - the labeled candidate partitions are consistent with the committed
//!     vector,
//!   - therefore the public tally is correct.
//!
//! We do NOT implement or modify any of the EPA prover/verifier equations
//! here. This module only:
//!   - regenerates the (deterministic, demo-only) KZG SRS the EPA code uses,
//!   - converts Aggios-level inputs into `epa::structs::{CommonInputs, Witness}`,
//!   - calls `epa::prover::generate_proof` / `epa::verifier::verify_proof`,
//!   - adds serialization for the proof object (the EPA crate has none),
//!   - measures proving/verification time and proof size.
//!
//! API mismatches we adapt to (documented, not changed):
//!   - The EPA implementation identifies each partition label by a *domain
//!     element index* (`vote_per_j: Vec<usize>`; label scalar = ω^index),
//!     not an arbitrary field element. The adapter deterministically maps
//!     partition position j (in the canonical Aggios order) to EPA label
//!     index j+1, and requires domain_size > number of partitions so the
//!     indices stay distinct. The Aggios hash labels w_j are still published
//!     and bound on the bulletin board.
//!   - Domain sizes must be powers of two (asserted by the EPA setup).
//!   - Empty partitions are filtered out deterministically on BOTH the prove
//!     and verify side before calling EPA (a zero-size partition is the empty
//!     set, which trivially exists, so this loses no soundness: the remaining
//!     nonempty subsets still form a disjoint cover of the whole domain).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations as EvaluationsOnDomain, GeneralEvaluationDomain};
use ark_poly_commit::kzg10::KZG10;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::test_rng;

use epa::prover::generate_proof;
use epa::structs::{CommonInputs, Proof, PublicParameters, Witness};
use epa::verifier::verify_proof;

use crate::error::{AggiosError, Result};

pub const EPA_PROOF_FORMAT_VERSION: u8 = 1;
pub const EPA_BACKEND_ID: &str = "epa-kzg10-bls12-381-arkworks-0.3";

/// A cached, deterministic SRS + domain for one power-of-two size.
///
/// SECURITY NOTE (demo only): the EPA benchmark generates the KZG SRS with
/// `ark_std::test_rng()`, i.e. a fixed seed. We reproduce exactly that setup
/// so that provers and validators independently derive the same parameters.
/// A production deployment needs a real trusted setup ceremony.
pub struct SrsBundle {
    pub pp: PublicParameters<Bls12_381>,
    pub srs_ref: String,
    lagrange_g1: OnceLock<Vec<G1Affine>>,
}

impl SrsBundle {
    pub fn domain_size(&self) -> usize {
        self.pp.domain.size()
    }

    /// Lagrange basis commitments B_i = [L_i(τ)]_1, computed once per size.
    pub fn lagrange_basis(&self) -> &[G1Affine] {
        self.lagrange_g1.get_or_init(|| {
            crate::domain::lagrange_basis_commitments(&self.pp.poly_ck.powers_of_g, &self.pp.domain)
        })
    }
}

fn srs_cache() -> &'static Mutex<HashMap<usize, Arc<SrsBundle>>> {
    static CACHE: OnceLock<Mutex<HashMap<usize, Arc<SrsBundle>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn srs_ref_for(n: usize) -> String {
    format!("{};deterministic-test-rng;n={}", EPA_BACKEND_ID, n)
}

/// Recreate the EPA public parameters for domain size `n` (power of two),
/// exactly as `setup()` in the EPA benchmark binary does. Results are cached.
pub fn get_or_create_srs(n: usize) -> Result<Arc<SrsBundle>> {
    if !n.is_power_of_two() {
        return Err(AggiosError::Domain(format!(
            "EPA requires a power-of-two domain size, got {}",
            n
        )));
    }
    if let Some(bundle) = srs_cache().lock().unwrap().get(&n) {
        return Ok(bundle.clone());
    }

    // Same construction as the EPA benchmark's setup(): KZG10 setup with the
    // deterministic test rng, then get_powers to obtain G1 and G2 chains.
    let max_degree = n;
    let rng = &mut test_rng();
    let srs = KZG10::<Bls12_381, DensePolynomial<Fr>>::setup(max_degree, true, rng)
        .map_err(|e| AggiosError::Epa(format!("KZG setup failed: {:?}", e)))?;
    let (poly_ck, g2_powers) = epa::kzg_helpers::get_powers::<Bls12_381>(&srs, max_degree);
    let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(n)
        .ok_or_else(|| AggiosError::Domain(format!("no evaluation domain of size {}", n)))?;

    let bundle = Arc::new(SrsBundle {
        pp: PublicParameters {
            poly_ck,
            g2_powers,
            domain,
            max_degree,
        },
        srs_ref: srs_ref_for(n),
        lagrange_g1: OnceLock::new(),
    });

    let mut cache = srs_cache().lock().unwrap();
    Ok(cache.entry(n).or_insert(bundle).clone())
}

/// Public input to the EPA proof, from the Aggios point of view.
#[derive(Clone, Debug)]
pub struct EpaPublicInput {
    pub election_id: String,
    pub aggregator_id: String,
    pub domain_size: usize,
    /// C_commit = Σ τ_i + Σ τ_pad_p (KZG commitment to the token vector).
    pub commitment_c: G1Affine,
    /// Aggios hash labels w_j, one per partition (candidates in display
    /// order, then NO_VOTE, then PAD). Published metadata; see module docs.
    pub labels: Vec<Fr>,
    /// EPA-level label indices (label scalar = ω^index), canonical mapping
    /// j -> j+1. Must be distinct and < domain_size.
    pub label_indices: Vec<usize>,
    /// Claimed partition sizes, same order as `labels`.
    pub sizes: Vec<usize>,
    /// Reference identifying the (deterministic) SRS/params.
    pub srs_ref: String,
}

impl EpaPublicInput {
    /// Canonical label-index mapping for `k` partitions: j -> j+1.
    pub fn canonical_label_indices(num_partitions: usize) -> Vec<usize> {
        (1..=num_partitions).collect()
    }

    fn validate(&self, bundle: &SrsBundle) -> Result<()> {
        if self.domain_size != bundle.domain_size() {
            return Err(AggiosError::Epa(format!(
                "domain_size {} does not match SRS domain {}",
                self.domain_size,
                bundle.domain_size()
            )));
        }
        if self.labels.len() != self.sizes.len() || self.labels.len() != self.label_indices.len() {
            return Err(AggiosError::Epa(
                "labels, label_indices and sizes must have equal length".into(),
            ));
        }
        if self.labels.is_empty() {
            return Err(AggiosError::Epa("at least one partition required".into()));
        }
        if self.sizes.iter().sum::<usize>() != self.domain_size {
            return Err(AggiosError::Epa(format!(
                "partition sizes sum to {} but domain size is {}",
                self.sizes.iter().sum::<usize>(),
                self.domain_size
            )));
        }
        // Label indices must be distinct domain indices (nonzero, < n) so the
        // EPA label scalars ω^index are pairwise distinct and != 1.
        let mut seen = std::collections::HashSet::new();
        for &idx in &self.label_indices {
            if idx == 0 || idx >= self.domain_size {
                return Err(AggiosError::Epa(format!(
                    "label index {} out of range 1..{}",
                    idx, self.domain_size
                )));
            }
            if !seen.insert(idx) {
                return Err(AggiosError::Epa(format!("duplicate label index {}", idx)));
            }
        }
        Ok(())
    }

    /// Deterministically drop empty partitions (both prover and verifier do
    /// this) and build the EPA `CommonInputs`.
    fn to_common_inputs(&self) -> (CommonInputs<Bls12_381>, Vec<usize>) {
        let mut vote_per_j = Vec::new();
        let mut subsets_sizes = Vec::new();
        let mut kept_positions = Vec::new();
        for (j, &size) in self.sizes.iter().enumerate() {
            if size > 0 {
                vote_per_j.push(self.label_indices[j]);
                subsets_sizes.push(size);
                kept_positions.push(j);
            }
        }
        (
            CommonInputs {
                c_comm: self.commitment_c,
                vote_per_j,
                subsets_sizes,
            },
            kept_positions,
        )
    }
}

/// Witness for the EPA proof, from the Aggios point of view.
#[derive(Clone, Debug)]
pub struct EpaWitness {
    /// Voter/padding token scalar values, one per domain index.
    pub values_by_index: Vec<Fr>,
    /// One partition per label (same order as EpaPublicInput.labels). The
    /// partitions must be disjoint and cover the whole domain.
    pub partition_indices: Vec<Vec<usize>>,
}

/// Serializable wrapper around the black-box EPA proof object.
pub struct EpaProof {
    pub inner: Proof<Bls12_381>,
}

impl Clone for EpaProof {
    fn clone(&self) -> Self {
        // epa::structs::Proof does not derive Clone; round-trip through the
        // canonical serialization instead (wrapper-level, black box intact).
        let bytes = self.to_bytes().expect("serializing a valid proof");
        EpaProof::from_bytes(&bytes).expect("deserializing bytes we just produced")
    }
}

fn write_vec<T: CanonicalSerialize>(out: &mut Vec<u8>, v: &[T]) -> Result<()> {
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    for item in v {
        item.serialize(&mut *out)
            .map_err(|e| AggiosError::Serialization(format!("{:?}", e)))?;
    }
    Ok(())
}

fn read_vec<T: CanonicalDeserialize>(bytes: &mut &[u8]) -> Result<Vec<T>> {
    if bytes.len() < 4 {
        return Err(AggiosError::Serialization("truncated proof".into()));
    }
    let (len_bytes, rest) = bytes.split_at(4);
    *bytes = rest;
    let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
    if len > 1 << 24 {
        return Err(AggiosError::Serialization("implausible vector length".into()));
    }
    let mut items = Vec::with_capacity(len);
    for _ in 0..len {
        let item = T::deserialize(&mut *bytes)
            .map_err(|e| AggiosError::Serialization(format!("{:?}", e)))?;
        items.push(item);
    }
    Ok(items)
}

fn read_one<T: CanonicalDeserialize>(bytes: &mut &[u8]) -> Result<T> {
    T::deserialize(&mut *bytes).map_err(|e| AggiosError::Serialization(format!("{:?}", e)))
}

impl EpaProof {
    /// Canonical compressed serialization (version-prefixed).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = vec![EPA_PROOF_FORMAT_VERSION];
        write_vec(&mut out, &self.inner.round1proof.x_comm)?;
        self.inner
            .round1proof
            .z_0_comm
            .serialize(&mut out)
            .map_err(|e| AggiosError::Serialization(format!("{:?}", e)))?;
        write_vec(&mut out, &self.inner.round1proof.z_nonzero_comm)?;
        write_vec(&mut out, &self.inner.round1proof.v_comm)?;
        write_vec(&mut out, &self.inner.round1proof.y_comm)?;
        self.inner
            .p_0_comm
            .serialize(&mut out)
            .map_err(|e| AggiosError::Serialization(format!("{:?}", e)))?;
        write_vec(&mut out, &self.inner.p_nonzero_comm)?;
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = bytes;
        if cursor.is_empty() || cursor[0] != EPA_PROOF_FORMAT_VERSION {
            return Err(AggiosError::Serialization(
                "unknown EPA proof format version".into(),
            ));
        }
        cursor = &cursor[1..];
        let x_comm: Vec<G1Affine> = read_vec(&mut cursor)?;
        let z_0_comm: G1Affine = read_one(&mut cursor)?;
        let z_nonzero_comm: Vec<G2Affine> = read_vec(&mut cursor)?;
        let v_comm: Vec<G1Affine> = read_vec(&mut cursor)?;
        let y_comm: Vec<G1Affine> = read_vec(&mut cursor)?;
        let p_0_comm: G2Affine = read_one(&mut cursor)?;
        let p_nonzero_comm: Vec<G1Affine> = read_vec(&mut cursor)?;
        Ok(EpaProof {
            inner: Proof {
                round1proof: epa::structs::Round1Proof {
                    x_comm,
                    z_0_comm,
                    z_nonzero_comm,
                    v_comm,
                    y_comm,
                },
                p_0_comm,
                p_nonzero_comm,
            },
        })
    }
}

pub struct EpaProofResult {
    pub proof: EpaProof,
    /// The existing EPA implementation only exposes *blinded* partition
    /// commitments inside the proof, with no opening API, so per-partition
    /// subcommitments usable for voter receipts are not available.
    pub partition_commitments: Option<Vec<G1Affine>>,
    pub proving_time_ms: u128,
    pub proof_size_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub verification_time_ms: u128,
}

fn validate_witness(public_input: &EpaPublicInput, witness: &EpaWitness) -> Result<()> {
    let n = public_input.domain_size;
    if witness.values_by_index.len() != n {
        return Err(AggiosError::Epa(format!(
            "witness has {} values but domain size is {}",
            witness.values_by_index.len(),
            n
        )));
    }
    if witness.partition_indices.len() != public_input.sizes.len() {
        return Err(AggiosError::Epa(
            "witness partition count does not match public sizes".into(),
        ));
    }
    let mut covered = vec![false; n];
    for (j, part) in witness.partition_indices.iter().enumerate() {
        if part.len() != public_input.sizes[j] {
            return Err(AggiosError::Epa(format!(
                "partition {} has {} indices but claimed size {}",
                j,
                part.len(),
                public_input.sizes[j]
            )));
        }
        for &i in part {
            if i >= n {
                return Err(AggiosError::Epa(format!("index {} out of domain", i)));
            }
            if covered[i] {
                return Err(AggiosError::Epa(format!("index {} appears twice", i)));
            }
            covered[i] = true;
        }
    }
    if covered.iter().any(|c| !c) {
        return Err(AggiosError::Epa(
            "partitions do not cover the whole domain".into(),
        ));
    }
    Ok(())
}

/// Call the black-box EPA prover.
pub fn prove(
    bundle: &SrsBundle,
    public_input: &EpaPublicInput,
    witness: &EpaWitness,
) -> Result<EpaProofResult> {
    public_input.validate(bundle)?;
    validate_witness(public_input, witness)?;

    let (common_inputs, kept_positions) = public_input.to_common_inputs();
    if common_inputs.subsets_sizes.is_empty() {
        return Err(AggiosError::Epa("all partitions are empty".into()));
    }

    // Interpolate the committed polynomial C from the token values.
    let c_values = witness.values_by_index.clone();
    let c_poly =
        EvaluationsOnDomain::from_vec_and_domain(c_values.clone(), bundle.pp.domain).interpolate();

    #[cfg(debug_assertions)]
    {
        // Consistency check (debug only): commitment_c must be the KZG
        // commitment of the interpolated token vector.
        let recomputed = epa::kzg_helpers::g1_commit::<Bls12_381>(&bundle.pp.poly_ck, &c_poly);
        if recomputed != public_input.commitment_c {
            return Err(AggiosError::Epa(
                "commitment_c does not match the witness values".into(),
            ));
        }
    }

    let subsets_indices: Vec<Vec<usize>> = kept_positions
        .iter()
        .map(|&j| {
            let mut indices = witness.partition_indices[j].clone();
            indices.sort_unstable();
            indices
        })
        .collect();

    let epa_witness = Witness {
        subsets_indices,
        c_poly,
        c_values,
    };

    let start = Instant::now();
    let proof = generate_proof::<Bls12_381, _>(
        &bundle.pp,
        &common_inputs,
        &epa_witness,
        &mut rand::thread_rng(),
    );
    let proving_time_ms = start.elapsed().as_millis();

    let proof = EpaProof { inner: proof };
    let proof_size_bytes = proof.to_bytes()?.len();

    Ok(EpaProofResult {
        proof,
        partition_commitments: None,
        proving_time_ms,
        proof_size_bytes,
    })
}

/// Structural check: the proof's commitment vectors must match the number of
/// nonempty partitions `k`, otherwise the black-box verifier can panic with
/// out-of-bounds indexing on adversarial inputs. (Wrapper-level check only;
/// EPA internals untouched.)
fn proof_shape_matches(proof: &Proof<Bls12_381>, k: usize) -> bool {
    proof.round1proof.x_comm.len() == k
        && proof.round1proof.v_comm.len() == k
        && proof.round1proof.z_nonzero_comm.len() == k - 1
        && proof.p_nonzero_comm.len() == k - 1
        && proof.round1proof.y_comm.len() == k.saturating_sub(2)
}

/// Call the black-box EPA verifier.
pub fn verify(
    bundle: &SrsBundle,
    public_input: &EpaPublicInput,
    proof: &EpaProof,
) -> Result<VerificationResult> {
    public_input.validate(bundle)?;
    let (common_inputs, _) = public_input.to_common_inputs();
    if common_inputs.subsets_sizes.is_empty() {
        return Err(AggiosError::Epa("all partitions are empty".into()));
    }

    let start = Instant::now();
    if !proof_shape_matches(&proof.inner, common_inputs.subsets_sizes.len()) {
        return Ok(VerificationResult {
            valid: false,
            verification_time_ms: start.elapsed().as_millis(),
        });
    }

    // The EPA code can panic on malformed proofs; treat any panic as an
    // invalid proof rather than crashing the validator.
    let valid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_proof(&bundle.pp, &common_inputs, &proof.inner)
    }))
    .unwrap_or(false);
    let verification_time_ms = start.elapsed().as_millis();

    Ok(VerificationResult {
        valid,
        verification_time_ms,
    })
}
