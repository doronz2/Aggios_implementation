//! Domain helpers: Lagrange basis commitments, padding token scalars.
//!
//! For a radix-2 evaluation domain H = {ω^0, ..., ω^{n-1}} and KZG SRS powers
//! [τ^k]_1, the commitment to the i-th Lagrange basis polynomial L_i is
//!
//!   B_i = [L_i(τ)]_1 = (1/n) Σ_k ω^{-ik} [τ^k]_1
//!
//! i.e. the vector (B_0, ..., B_{n-1}) is the inverse DFT of the SRS points
//! over the group. We compute all of them at once with a radix-2 FFT over G1
//! (O(n log n) scalar multiplications) instead of committing each L_i
//! separately (O(n^2)).

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::One;
use rayon::prelude::*;

use crate::hash::hash_to_fr;

pub const PAD_TOKEN_SEP: &[u8] = b"AGGIOS_PAD_TOKEN";

pub fn next_power_of_two(n: usize) -> usize {
    n.max(1).next_power_of_two()
}

/// Deterministic public padding scalar for padding index p:
///   pad_scalar_p = hash_to_fr("AGGIOS_PAD_TOKEN" || election_id || aggregator_id || p)
pub fn pad_scalar(election_id: &str, aggregator_id: &str, pad_index: usize) -> Fr {
    hash_to_fr(
        PAD_TOKEN_SEP,
        &[
            election_id.as_bytes(),
            aggregator_id.as_bytes(),
            &(pad_index as u64).to_le_bytes(),
        ],
    )
}

fn bit_reverse(mut value: usize, bits: u32) -> usize {
    let mut result = 0;
    for _ in 0..bits {
        result = (result << 1) | (value & 1);
        value >>= 1;
    }
    result
}

/// In-place radix-2 Cooley–Tukey FFT over G1 with twiddle scalar `omega`
/// (a primitive n-th root of unity in Fr).
fn group_fft_in_place(points: &mut [G1Projective], omega: Fr) {
    let n = points.len();
    assert!(n.is_power_of_two(), "group FFT needs a power-of-two size");
    let log_n = n.trailing_zeros();

    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if j > i {
            points.swap(i, j);
        }
    }

    let mut len = 2;
    while len <= n {
        let w_len = omega.pow([(n / len) as u64]);
        points.par_chunks_mut(len).for_each(|chunk| {
            let half = len / 2;
            let mut w = Fr::one();
            for j in 0..half {
                // butterfly: (u, v) -> (u + w·v, u - w·v)
                let t = chunk[j + half].mul(w.into_repr());
                let u = chunk[j];
                chunk[j] = u + t;
                chunk[j + half] = u - t;
                w *= w_len;
            }
        });
        len <<= 1;
    }
}

/// Compute all Lagrange basis commitments B_i = [L_i(τ)]_1 from the SRS
/// powers [1]_1, [τ]_1, ..., [τ^{n-1}]_1 (inverse group DFT).
pub fn lagrange_basis_commitments(
    powers_of_g: &[G1Affine],
    domain: &GeneralEvaluationDomain<Fr>,
) -> Vec<G1Affine> {
    let n = domain.size();
    assert!(
        powers_of_g.len() >= n,
        "SRS has fewer than domain-size powers"
    );

    let mut points: Vec<G1Projective> = powers_of_g[..n]
        .par_iter()
        .map(|p| p.into_projective())
        .collect();

    // Inverse DFT: FFT with ω^{-1}, then scale by 1/n.
    let omega_inv = domain
        .element(1)
        .inverse()
        .expect("domain generator is nonzero");
    group_fft_in_place(&mut points, omega_inv);

    let n_inv = Fr::from(n as u64)
        .inverse()
        .expect("domain size is nonzero mod r");
    let scaled: Vec<G1Projective> = points
        .par_iter()
        .map(|p| p.mul(n_inv.into_repr()))
        .collect();

    ProjectiveCurve::batch_normalization_into_affine(&scaled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::{Evaluations as EvaluationsOnDomain, UVPolynomial};
    use ark_std::Zero;
    use epa::kzg_helpers::g1_commit;

    #[test]
    fn lagrange_commitments_match_direct_kzg_commitments() {
        let n = 8usize;
        let pp = crate::epa_adapter::get_or_create_srs(n).expect("srs");
        let basis = lagrange_basis_commitments(&pp.pp.poly_ck.powers_of_g, &pp.pp.domain);
        assert_eq!(basis.len(), n);

        for i in 0..n {
            // L_i = interpolation of the i-th unit vector
            let mut values = vec![Fr::zero(); n];
            values[i] = Fr::one();
            let l_i: DensePolynomial<Fr> =
                EvaluationsOnDomain::from_vec_and_domain(values, pp.pp.domain).interpolate();
            let direct = g1_commit::<Bls12_381>(&pp.pp.poly_ck, &l_i);
            assert_eq!(basis[i], direct, "Lagrange commitment mismatch at {}", i);
        }
    }

    #[test]
    fn pad_scalars_are_deterministic_and_distinct() {
        let a = pad_scalar("e1", "A1", 0);
        let b = pad_scalar("e1", "A1", 0);
        let c = pad_scalar("e1", "A1", 1);
        let d = pad_scalar("e1", "A2", 0);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }
}
