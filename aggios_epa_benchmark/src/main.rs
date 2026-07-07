pub mod kzg_helpers;
pub mod prover;
pub mod structs;
pub mod utils;
pub mod verifier;
pub mod fast_div;

use ark_bls12_381::{Bls12_381};
use ark_ec::PairingEngine;
use ark_poly::{GeneralEvaluationDomain, EvaluationDomain, Evaluations as EvaluationsOnDomain, univariate::DensePolynomial};
use ark_poly_commit::kzg10::KZG10;
use ark_std::{test_rng, UniformRand}; // same rng all executions, useful for debugging
use std::{time::Instant};

use crate::kzg_helpers::g1_commit;
use crate::prover::generate_proof;
use crate::verifier::verify_proof;
use crate::structs::{PublicParameters, Witness, CommonInputs};
use crate::utils::get_random_votes;
// use crate::utils::save_proof;


// Create the public parameters
// Todo can be saved in a file
fn setup<E: PairingEngine>(n: usize) -> PublicParameters<E> {
    println!("Generating public parameters");
    // We need to create a domain of at least n elements.
    // We currently only deal with the case where degree is a power of 2
    assert_eq!(n & (n - 1), 0, "Whole set size must be a power of 2"); 

    let max_degree = n;  // we need to commit to Z_h = X^n - 1 hence at least n elements in the SRS.
    println!("...Generating KZG SRS for degree up to {:?}", max_degree);

    // should rather use real RNG, but this is sufficient for PoC.
    let rng = &mut test_rng();
    let now = Instant::now();
    let srs = KZG10::<E, DensePolynomial<E::Fr>>::setup(max_degree, true, rng).unwrap();

    // get the chains of powers both in G1 and G2
    let (poly_ck, g2_powers) = kzg_helpers::get_powers::<E>(&srs, max_degree);

    println!("......Took {:?}", now.elapsed());

    // Create domain H
    println!("...Setting up domain of size {:?}", n);
    let now = Instant::now();
    let domain: GeneralEvaluationDomain<E::Fr> = GeneralEvaluationDomain::new(n).unwrap();
    println!("......Took {:?}", now.elapsed());

    return PublicParameters {
        poly_ck,
        g2_powers,
        domain,
        max_degree,
    }
}


fn main() {
    let mut rng = test_rng();

    let bitsize_values = 8..19;
    let k_values = [2, 3, 4, 5, 6, 7, 8, 9, 10, 30, 50, 100];
    let n_runs = 50;
    // let bitsize_values = 10..11;
    // let k_values = [2];
    // let n_runs = 2;

    for bitsize in bitsize_values {
        println!("#### n = 2^{:?} ####", bitsize);
        let n = 1 << bitsize;
        let now = Instant::now();
        let pp = setup::<Bls12_381>(n);
        println!("Generated public setup in {:?}", now.elapsed());

        for desired_k in k_values {
            println!("==== k = {:?} =====", desired_k);
            for run in 0..n_runs {
                println!("---- run {:?} / {:?} ----", run + 1, n_runs);

                println!("Generating witness and common inputs");
                let now = Instant::now();
                println!("...Generating a random C instance and its commitment");

                // Create a random poly C from totalsize random elements (technically should be nonzero but probability is negligible)
                let c_values: Vec<<Bls12_381 as PairingEngine>::Fr> = (0..n).map(|_| <Bls12_381 as PairingEngine>::Fr::rand(&mut rng)).collect();
                let c_poly = EvaluationsOnDomain::from_vec_and_domain(c_values.clone(), pp.domain).interpolate();

                let c_comm = g1_commit(&pp.poly_ck, &c_poly);

                // Create public parameters (that include a commit to C)
                println!("......Took {:?}", now.elapsed());

                println!("...Generating random partition of {:?} elements with {:?} subsets", n, desired_k);
                let now = Instant::now();
                let mut k = 0;
                let mut subsets_indices = vec![vec![]];  // fake init to make compiler happy
                let mut k_fake = desired_k;  // increase the number of desired partitions until we get k nonempty partitions

                while k != desired_k {
                    subsets_indices = get_random_votes(n, k_fake);
                    k = subsets_indices.len();
                    k_fake += desired_k - k;
                }
                let k = subsets_indices.len();

                // println!("We will use the following partition: {:?}", subsets_indices);

                let vote_per_j: Vec<usize> = (1..(k+1)).collect();
                assert_eq!(vote_per_j.len(), subsets_indices.len());
                // println!("The votes of the sets are for candidates: {:?}", vote_per_j);
                println!("......Took {:?}", now.elapsed());


                let witness = Witness {
                    c_poly,
                    c_values,
                    subsets_indices: subsets_indices.clone(),
                };

                let subsets_sizes = subsets_indices.iter().map(|k| k.len()).collect();
                let common_inputs = CommonInputs {
                    c_comm,
                    subsets_sizes,
                    vote_per_j: vote_per_j.clone(),
                };
                println!("Common input generation took {:?}", now.elapsed());

                println!("Running prover");
                let now = Instant::now();
                let proof = generate_proof::<Bls12_381, _>(&pp, &common_inputs, &witness, &mut rng);
                println!("Prover took {:?}", now.elapsed());

                // save_proof::<Bls12_381>(&proof, &format!("bin/proof_n_{}_k_{}.bin", total_size, subsets_indices.len()));

                println!("Running verifier");
                let now = Instant::now();
                let verif = verify_proof(&pp, &common_inputs, &proof);
                println!("Verification took {:?}", now.elapsed());

                if verif {
                    println!("Verifier says the proof is true");
                } else {
                    println!("\x1b[91m!!!!Verifier says the proof is false!!!!\x1b[0m");
                }
            }
        }
    }
}
