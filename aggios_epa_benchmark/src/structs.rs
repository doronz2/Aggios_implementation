use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_poly::{GeneralEvaluationDomain, univariate::DensePolynomial};
use ark_poly_commit::kzg10::Powers;
use merlin::Transcript;
use std::marker::PhantomData;
use ark_serialize::CanonicalSerialize;


pub struct AggiosTranscript<F: PrimeField> {
    transcript: Transcript,
    phantom: PhantomData<F>,
}

impl<F:PrimeField> Default for AggiosTranscript<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F:PrimeField> AggiosTranscript<F> {
    pub fn new() -> Self {
        Self {
            transcript: Transcript::new(b"Init Aggios transcript"),
            phantom: PhantomData::default(),
        }
    }

    // Get a uniform random field element for field size < 384
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> F {
        let mut bytes = [0u8;64];
        self.transcript.challenge_bytes(label, &mut bytes);
        let challenge = F::from_le_bytes_mod_order(bytes.as_ref());
        self.append_element(b"append_challenge", &challenge);
        challenge
    }

    // Append field/group element to the transcript
    pub fn append_element<T: CanonicalSerialize>(&mut self, label: &'static [u8], r: &T) {
        let mut buf = vec![];
        r.serialize(&mut buf).unwrap();
        self.transcript.append_message(label, buf.as_ref());
    }
}

// Common inputs, available to the verifier
pub struct PublicParameters<E: PairingEngine> {
    pub poly_ck: Powers<'static, E>,  // List of powers of g1
    pub g2_powers: Vec<E::G2Affine>,  // list of powers of g2
    pub domain: GeneralEvaluationDomain<E::Fr>,  // Domain H
    pub max_degree: usize,  // Max degree commitment (= poly_ck.len() - 1)
}

pub struct CommonInputs<E:PairingEngine> {
    pub c_comm: E::G1Affine,
    pub vote_per_j: Vec<usize>,  // For each I_j, declare for which candidate these votes are
    pub subsets_sizes: Vec<usize>,  // List of m_j,
}

pub struct Witness<E:PairingEngine> {
    pub subsets_indices: Vec<Vec<usize>>,
    pub c_poly: DensePolynomial<E::Fr>,
    pub c_values: Vec<E::Fr>,  // c_values[i] = c_poly(omega^i). Usefult for building V
}

pub struct Proof<E:PairingEngine> {
    pub round1proof: Round1Proof<E>,
    pub p_0_comm: E::G2Affine,
    pub p_nonzero_comm: Vec<E::G1Affine>,
}

pub struct Round1Proof<E:PairingEngine> {
    pub x_comm: Vec<E::G1Affine>,  // Commitments to x_j(X)
    pub z_0_comm: E::G1Affine,  // [z_0(X)]_1
    pub z_nonzero_comm: Vec<E::G2Affine>,  // [z_j(X)]_2
    pub v_comm: Vec<E::G1Affine>,
    pub y_comm: Vec<E::G1Affine>,
}
