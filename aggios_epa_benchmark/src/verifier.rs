use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::UniformRand;
use ark_poly::EvaluationDomain;
use ark_std::{Zero, One};
use std::time::Instant;
use rayon::prelude::*;

use crate::kzg_helpers::{g1_commit_sparse, g2_commit_sparse};
use crate::structs::{PublicParameters, Proof, CommonInputs};
use crate::utils::get_challenges;


pub fn verify_proof<E:PairingEngine>(
    pp: &PublicParameters<E>,
    common_inputs: &CommonInputs<E>,
    proof: &Proof<E>,
) -> bool {

    // Initialise and fill in the transcript to get the challenges
    let challenges = get_challenges(&proof.round1proof, &common_inputs);
    let pairings_to_check = build_pairings_to_check(&pp, &common_inputs, &proof, &challenges);

    check_pairings(&pp, pairings_to_check)
}


fn build_pairings_to_check<E:PairingEngine>(pp:&PublicParameters<E>, common_inputs: &CommonInputs<E>, proof: &Proof<E>, challenges: &Vec<E::Fr>) -> Vec<(E::G1Affine, E::G2Affine, E::G1Affine, E::G2Affine)> {
    println!("...Building the pairings to check");
    let now = Instant::now();
    // let mut pairings_to_check = Vec::with_capacity(common_inputs.vote_per_j.len());
    let mut pairings_to_check = vec![(E::G1Affine::zero(), E::G2Affine::zero(), E::G1Affine::zero(), E::G2Affine::zero()); common_inputs.vote_per_j.len()];

    // let z_h: DensePolynomial<E::Fr> = pp.domain.vanishing_polynomial().into();
    // let z_h_commit1 = g1_commit(&pp.poly_ck, &z_h);
    let z_h_coeffs = vec![(0, -E::Fr::one()), (pp.max_degree, E::Fr::one())];
    let z_h_commit1 = g1_commit_sparse(&pp.poly_ck, &z_h_coeffs);

    // We need to adapt y_comm to include y1 = [z1] (paper notation) and yn = z_H
    let mut y_comm_full = vec!(proof.round1proof.z_0_comm);
    y_comm_full.append(&mut {proof.round1proof.y_comm.clone()});
    y_comm_full.push(z_h_commit1);

    // INDEX NOTATION IS DIFFERENT THAN IN THE PAPER
    // Paper is nicely intuitively indexed
    // Here all vectors indexes start at 0, even when the first item,
    // because in G1 and not G2 (or vice versa), is not in the vector
    // (e.g z_1 paper matches z_0_comm, z_2 paper -> z_nonzero_comm[0], ...)

    let one_g2 = g2_commit_sparse::<E>(&pp.g2_powers, &vec![(0, E::Fr::one())]);  // [1]_2 (commit to 1 in G2)

    pairings_to_check.par_iter_mut().enumerate().for_each(|(j, to_check)| {
        if j == 0 {
            // Case j = 1 in the paper
            // -----------------------

            // e(z_1, p_1 + phi [X^d-m_1]) = e([Z_h] + chi([C] - v_1 [v_1]) + phi x_1, 1)
            // phi cannot be chi^2 because of last challenge attacks

            // TODO might be faster using the GProjective groups rather than the GAffine

            let monomial_coeffs = vec![(pp.max_degree - common_inputs.subsets_sizes[0], E::Fr::one())];
            let monomial_commit = g2_commit_sparse::<E>(&pp.g2_powers, &monomial_coeffs);

            let chi = challenges[0];
            let rng = &mut ark_std::test_rng();
            let phi = E::Fr::rand(rng);

            let b_1 = proof.p_0_comm
                    + monomial_commit.mul(phi).into();
            let c_1 = z_h_commit1
                    + (common_inputs.c_comm + proof.round1proof.v_comm[0].mul(-pp.domain.element(common_inputs.vote_per_j[0])).into()).mul(chi).into()
                    + proof.round1proof.x_comm[0].mul(phi).into();

            *to_check = (proof.round1proof.z_0_comm, b_1, c_1, one_g2);
        }

        else {
            // General case j in the paper
            // ---------------------------
            let chi = challenges[j];
            let rng = &mut ark_std::test_rng();
            let phi = E::Fr::rand(rng);
            let phi2 = phi * phi;

            let monomial_coeffs = vec![(pp.max_degree - common_inputs.subsets_sizes[j], E::Fr::one())];
            let monomial_commit = g1_commit_sparse::<E>(&pp.poly_ck, &monomial_coeffs);

            // e(p_j + phi [X^d-m_j] + phi^2 y_j-1, z_j) = e([Z_H] + chi([C] - v_j[V_j'] + phi x_j + phi^2 y_j, 1)

            let a_j = proof.p_nonzero_comm[j - 1]
                    + monomial_commit.mul(phi).into()
                    + y_comm_full[j - 1].mul(phi2).into();

            let c_j = z_h_commit1
                    + (common_inputs.c_comm + proof.round1proof.v_comm[j].mul(-pp.domain.element(common_inputs.vote_per_j[j])).into()).mul(chi).into()
                    + proof.round1proof.x_comm[j].mul(phi).into()
                    + y_comm_full[j].mul(phi2).into();

            *to_check = (a_j, proof.round1proof.z_nonzero_comm[j - 1], c_j, one_g2);
        }
    });

    println!("......Took {:?}", now.elapsed());
    pairings_to_check
}


// Receives a list of pairing checks [(a, b, c, 1), ...] such that we should have e(a, b) - e(c, 1) = 0
// Instead of checking all pairings individually e(a_i, b_i) = e(c_i, 1) we check that
// sum_i e(a_i, b_i) + e(-c_i, 1) = 0 (note the - sign in front of c_i)
// To avoid adversary cases, we do not check the above sum but rather the sum
// sum_i [e([z^i]*a_i, b_i) + e([-z^i] * c_i, 1)] = 0 where z is a random scalar
// This can be batched into checking that e(sum_i [-z^i] c_i, 1) + sum_i e([z^i] a_i, b_i) = 0
fn check_pairings<E:PairingEngine>(pp: &PublicParameters<E>, pairing_checks: Vec<(E::G1Affine, E::G2Affine, E::G1Affine, E::G2Affine)>) -> bool {
    println!("...Checking {:?} pairings together", pairing_checks.len() + 1);
    let now = Instant::now();

    let mut prepared_pairings = vec!();

    let rng = &mut ark_std::test_rng();
    let z = E::Fr::rand(rng);
    let mut r = z;

    let mut accumulated_c = E::G1Affine::zero();

    for (a, b, c, _) in pairing_checks.iter() {
        // push e([z^i]*a_i, b_i) into the pairings to check
        prepared_pairings.push((E::G1Prepared::from(a.mul(r).into()), E::G2Prepared::from(b.clone())));

        let c = c.mul(-r);  // use -c instead of c
        accumulated_c = accumulated_c + c.into();
        r *= z;
    }

    // push e(sum_i [-z^i] c_i, 1) into the pairings to check
    let one_g2_prepared = E::G2Prepared::from(g2_commit_sparse::<E>(&pp.g2_powers, &vec![(0, E::Fr::one())]));
    prepared_pairings.push((E::G1Prepared::from(accumulated_c.into()), one_g2_prepared));

    // return true if the product is 1 (multiplicative notation)
    let res = E::product_of_pairings(prepared_pairings.iter()).is_one();

    // println!("product check gives us the result {:?}", res);
    println!("......Took {:?}", now.elapsed());
    return res
}
