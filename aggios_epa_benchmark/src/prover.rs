use ark_ec::PairingEngine;
use ark_ff::{Field, UniformRand};
use ark_poly::{UVPolynomial, GeneralEvaluationDomain, EvaluationDomain, Evaluations as EvaluationsOnDomain, univariate::DensePolynomial};
use ark_std::{One, Zero, rand::RngCore};

use std::time::Instant;
use rayon::prelude::*;

use crate::fast_div::poly_div;
use crate::kzg_helpers::{g1_commit, g2_commit};
use crate::structs::{PublicParameters, CommonInputs, Witness, Proof, Round1Proof};
use crate::utils::get_challenges;

type VecOfPolys<T> = Vec<DensePolynomial<T>>;


// V_j(X) = v_j^-1 * sum_{k in Ij} C(\omega^k) lambda_i(X) where lambda are the Lagrange over the complete set of size n
fn create_v_polys<E:PairingEngine>(witness: &Witness<E>, vote_per_j: &Vec<usize>, pp: &PublicParameters<E>) -> VecOfPolys<E::Fr> {
    println!("...Generating witnesses V_j(X)");
    let now = Instant::now();
    // let c_poly = &witness.c_poly;
    let subsets_indices = &witness.subsets_indices;

    assert_eq!(vote_per_j.len(), subsets_indices.len());
    let zero_poly = DensePolynomial::<E::Fr>::zero();
    let zero = E::Fr::zero();

    let mut v_polys = vec![zero_poly; subsets_indices.len()];

    // Parallel iteration over the j
    v_polys.par_iter_mut().enumerate().for_each(|(j, v_poly)| {
        let mut v_values = vec![zero; pp.domain.size()];
        for &i in subsets_indices[j].iter() {
            // Using c_values instead of c_poly.evaluate() reduces average complexity from O(n^2) to O(n)
            v_values[i] = witness.c_values[i];
        }

        // update v_polys[j]
        let temp = &EvaluationsOnDomain::from_vec_and_domain(v_values, pp.domain).interpolate() * pp.domain.element(vote_per_j[j]).inverse().unwrap();
        *v_poly = temp;
    });
    
    println!("......Took {:?}", now.elapsed());
    v_polys
}


// A "recursive" algorithm that computes the poly (but takes away the recursion for more efficiency)
// does not seem faster though
#[warn(dead_code)]
pub fn create_vanishing_poly_opt<E:PairingEngine>(positions: &[usize], domain: &GeneralEvaluationDomain<E::Fr>) -> DensePolynomial<E::Fr> {
    let mut polys = Vec::with_capacity(positions.len());
    for &i in positions.iter() {
        polys.push(DensePolynomial::from_coefficients_slice(&[-domain.element(i), E::Fr::one()]));
    }

    while polys.len() > 1 {        
        let mut new_polys = Vec::with_capacity((positions.len() + 1)/ 2);
        for i in 0..polys.len()/2 {
            new_polys.push(&polys[2 * i] * &polys[2 * i + 1]);
        }

        if polys.len() % 2 == 1 {
            new_polys.push(polys[polys.len() - 1].clone())
        }
        polys = new_polys;
    }

    return polys[0].clone()
}

// Average cost: O(n log^2 n) for n points, since multiplication is FFT of cost O(n log n)
pub fn create_vanishing_poly_recursive<E:PairingEngine>(positions: &[usize], domain: &GeneralEvaluationDomain<E::Fr>) -> DensePolynomial<E::Fr> {
    if positions.len() == 0 {
        return DensePolynomial::from_coefficients_slice(&[E::Fr::one()]);
    }
    if positions.len() == 1 {
        return DensePolynomial::from_coefficients_slice(&[-domain.element(positions[0]), E::Fr::one()]);
    }

    let middle = positions.len() / 2;
    return &create_vanishing_poly_recursive::<E>(&positions[..middle], domain) * &create_vanishing_poly_recursive::<E>(&positions[middle..], domain)
}

fn generate_vanishing_polys<E:PairingEngine>(witness: &Witness<E>, pp: &PublicParameters<E>) -> VecOfPolys<E::Fr> {
    println!("...Generating vanishing polys Z_j");
    let now = Instant::now();

    let zero_poly = DensePolynomial::<E::Fr>::zero();
    let mut z_polys = vec![zero_poly; witness.subsets_indices.len()];

    z_polys.par_iter_mut().enumerate().for_each(|(j, z_poly)| {
        *z_poly = create_vanishing_poly_recursive::<E>(witness.subsets_indices[j].as_slice(), &pp.domain)
    });
   
   println!("......Took {:?}", now.elapsed());
   z_polys
}

fn generate_blinders<E:PairingEngine, R:RngCore>(witness: &Witness<E>, rng: &mut R) -> (Vec<E::Fr>, Vec<E::Fr>) {
    println!("...Generating blinders");
    let now = Instant::now();

    let mut r_blinders = vec!();
    let mut s_blinders = vec!();

    let mut r_acc = E::Fr::one();
    // we should technically sample the r blinders from F* rather than F but the probability to get 0 is negligible
    for _ in 0..witness.subsets_indices.len() - 1{
        s_blinders.push(E::Fr::rand(rng));

        let r_j = E::Fr::rand(rng);
        r_acc = r_acc * r_j;
        r_blinders.push(r_j);
    }

    s_blinders.push(E::Fr::rand(rng));
    // r_k = (prod r_j)^-1
    r_blinders.push(r_acc.inverse().unwrap());

    println!("......Took {:?}", now.elapsed());
    (r_blinders, s_blinders)
}

fn generate_blinded_z_v<E:PairingEngine>(
    z_polys: &VecOfPolys<E::Fr>,
    v_polys: &VecOfPolys<E::Fr>,
    r_blinders: &Vec<E::Fr>,
    s_blinders: &Vec<E::Fr>)
 -> (VecOfPolys<E::Fr>, VecOfPolys<E::Fr>) {
    assert_eq!(z_polys.len(), v_polys.len());
    let now = Instant::now();
    println!("...Blinding polys");
    let mut blinded_z_polys = vec!();
    let mut blinded_v_polys = vec!();

    for j in 0..z_polys.len() {
        let blinded_z_j_poly = &z_polys[j] * r_blinders[j];
        let blinded_v_j_poly = &v_polys[j] + &(&blinded_z_j_poly * s_blinders[j]);
        blinded_z_polys.push(blinded_z_j_poly);
        blinded_v_polys.push(blinded_v_j_poly);
    }

    println!("......Took {:?}", now.elapsed());
    return (blinded_z_polys, blinded_v_polys)
}


fn generate_quotient_polys<E:PairingEngine>(
    witness: &Witness<E>,
    z_polys: &VecOfPolys<E::Fr>,
    r_blinders: &Vec<E::Fr>,
    v_polys: &VecOfPolys<E::Fr>,
    s_blinders: &Vec<E::Fr>,
    common_inputs: &CommonInputs<E>,
    pp: &PublicParameters<E>
) -> (VecOfPolys<E::Fr>, VecOfPolys<E::Fr>) {

    assert_eq!(z_polys.len(), r_blinders.len());
    assert_eq!(v_polys.len(), s_blinders.len());
    assert_eq!(v_polys.len(), z_polys.len());

    println!("...Generating quotient polys");
    let now = Instant::now();

    let mut p_1_polys = Vec::new();
    p_1_polys.resize(witness.subsets_indices.len(), DensePolynomial::from_coefficients_slice(&[E::Fr::zero()]));
    let mut p_2_polys = Vec::new();
    p_2_polys.resize(witness.subsets_indices.len(), DensePolynomial::from_coefficients_slice(&[E::Fr::zero()]));

    let z_h = pp.domain.vanishing_polynomial().into();

    // Parallel iteration over j on p1poly
    p_1_polys.par_iter_mut().enumerate().for_each(|(j, p_1_poly)| {
        let q_1_poly;
            q_1_poly = poly_div::<E>(&z_h, &z_polys[j]);

        let p_1_j_poly = &q_1_poly * r_blinders[j].inverse().unwrap();
        // update p1poly in the vector
        *p_1_poly = p_1_j_poly;
    });
    println!(".........P1j took {:?}", now.elapsed());
    let p2_time = Instant::now();

    // parallel iter over p2
    p_2_polys.par_iter_mut().enumerate().for_each(|(j, p_2_poly)| {
        let v_j_scalar = pp.domain.element(common_inputs.vote_per_j[j]);
        // let dividend = &witness.c_poly - &(&v_polys[j] * v_j_scalar);
        // We know that dividend is actually equal to C[omega^i] except on all the points of Ij where it is equal to 0 so we simply interpolate that
        // However the real bottleneck is the division itself
        let mut dividend_values = witness.c_values.clone();
        let zero = E::Fr::zero();
        for &i in witness.subsets_indices[j].iter() {
            dividend_values[i] = zero;
        }
        let dividend = EvaluationsOnDomain::from_vec_and_domain(dividend_values, pp.domain).interpolate();

        // let q_2_poly = &dividend / &z_polys[j];
        // assert_eq!(&q_2_poly * &z_polys[j], &witness.c_poly - &(&v_polys[j] * v_j_scalar), "z_j does not divide");
        let q_2_poly = poly_div::<E>(&dividend, &z_polys[j]);

        // Seems like there is no way to natively add a scalar to a poly so we create a poly of degree 0
        let neg_vs_blinder_poly = DensePolynomial::from_coefficients_slice(&[-v_j_scalar * s_blinders[j]]);
        let p_2_j_poly = &(&q_2_poly * r_blinders[j].inverse().unwrap()) + &neg_vs_blinder_poly;

        // update p2poly value in the vector
        *p_2_poly = p_2_j_poly;
    });

    println!(".........P2j took {:?}", p2_time.elapsed());
    println!("......Took {:?}", now.elapsed());
    (p_1_polys, p_2_polys)
}


fn generate_partial_accumulators<E:PairingEngine> (blinded_z_polys: &VecOfPolys<E::Fr>) -> VecOfPolys<E::Fr> {
    println!("...Generating partial accumulators");
    let now = Instant::now();
    // Some optimisation could be done by ordering the partitions by increasing size
    // Not the bottleneck though

    let mut partial_blinded_accs_polys = vec!();
    let mut partial_acc = blinded_z_polys[0].clone();

    for j in 1..blinded_z_polys.len() - 1 {
        partial_acc = &partial_acc * &blinded_z_polys[j];
        partial_blinded_accs_polys.push(partial_acc.clone());
    }

    // let z = DensePolynomial::from(pp.domain.vanishing_polynomial().into());
    // assert_eq!(z, &blinded_z_polys[blinded_z_polys.len() - 1] * &partial_blinded_accs_polys[partial_blinded_accs_polys.len() - 1]);
    
    println!("......Took {:?}", now.elapsed());
    partial_blinded_accs_polys
}


fn generate_commitments<E:PairingEngine>(
    x_polys: &VecOfPolys<E::Fr>,
    blinded_z_polys: &VecOfPolys<E::Fr>,
    blinded_v_polys: &VecOfPolys<E::Fr>,
    partial_blinded_accs_polys: &VecOfPolys<E::Fr>,
    pp: &PublicParameters<E>
) -> Round1Proof<E> {
    println!("...Committing {:?} elements", x_polys.len() + blinded_z_polys.len() + blinded_v_polys.len() + partial_blinded_accs_polys.len());
    let now = Instant::now();

    let zero_g1 = E::G1Affine::zero();
    let zero_g2 = E::G2Affine::zero();

    // [x_j]_1
    println!("....... x commit G1");
    let t = Instant::now();
    let mut x_comm = vec!();
    x_comm.resize(x_polys.len(), zero_g1);  // resize the vector, value used is irrelevent

    // In parallel, create the commits
    x_comm.par_iter_mut().enumerate().for_each(|(j, commit)| {
        *commit = g1_commit(&pp.poly_ck, &x_polys[j]);
    });
    println!("...... {:?}", t.elapsed());

    println!("....... z commit G2");
    let t = Instant::now();
    // [z_0] is committed in G1 whereas all the others are committed in G2. There is probably a simple way to put all this in one structure.
    let z_0_comm = g1_commit(&pp.poly_ck, &blinded_z_polys[0]);
    let mut z_nonzero_comm = vec!();
    z_nonzero_comm.resize(blinded_z_polys.len() - 1, zero_g2);

    z_nonzero_comm.par_iter_mut().enumerate().for_each(|(j, commit)| {
        *commit = g2_commit::<E>(&pp.g2_powers, &blinded_z_polys[j + 1]);
    });
    println!("...... {:?}", t.elapsed());

    // [v_j]_1
    println!("....... v commit G1");
    let t = Instant::now();
    let mut v_comm = vec!();
    v_comm.resize(blinded_v_polys.len(), zero_g1);

    v_comm.par_iter_mut().enumerate().for_each(|(j, commit)| {
        *commit = g1_commit(&pp.poly_ck, &blinded_v_polys[j]);
    });
    println!("...... {:?}", t.elapsed());

    // [y_j]_1 for 1 < j < k 
    println!("....... y commit G1");
    let t = Instant::now();
    let mut y_comm = vec!();
    y_comm.resize(partial_blinded_accs_polys.len(), zero_g1);

    y_comm.par_iter_mut().enumerate().for_each(|(j, commit)| {
        *commit = g1_commit(&pp.poly_ck, &partial_blinded_accs_polys[j]);
    });
    println!("...... {:?}", t.elapsed());


    println!("......Took {:?}", now.elapsed());
    Round1Proof {
        x_comm,
        z_0_comm,
        z_nonzero_comm,
        v_comm,
        y_comm
    }
}


fn generate_x_polys<E:PairingEngine>(subsets_indices: &Vec<Vec<usize>>, blinded_z_polys: &VecOfPolys<E::Fr>, pp:&PublicParameters<E>) -> VecOfPolys<E::Fr> {
    println!("...Generating degree check polys");
    let now = Instant::now();

    let mut x_polys = vec![];
    let zero_poly = DensePolynomial::from_coefficients_slice(&[E::Fr::zero()]);
    x_polys.resize(subsets_indices.len(), zero_poly);

    x_polys.par_iter_mut().enumerate().for_each(|(j, x_poly)| {
        let mut z_coeffs = blinded_z_polys[j].coeffs.clone();
        let mut res = Vec::with_capacity(pp.max_degree + 1);
        res.append(&mut vec![E::Fr::zero(); pp.max_degree - subsets_indices[j].len()]);
        res.append(&mut z_coeffs);
        *x_poly = DensePolynomial::from_coefficients_vec(res);
        // let monomial = SparsePolynomial::from_coefficients_slice(&[(pp.max_degree - subsets_indices[j].len(), E::Fr::one())]).into();
        // *x_poly = &monomial * &blinded_z_polys[j];
    });

    println!(".......Took {:?}", now.elapsed());
    x_polys
}


pub fn generate_proof<E:PairingEngine, R:RngCore>(
    pp: &PublicParameters<E>,
    common_inputs: &CommonInputs<E>,
    witness: &Witness<E>,
    rng: &mut R
) -> Proof<E> {

    // Generate the V_Ij
    let v_polys = create_v_polys(&witness, &common_inputs.vote_per_j, &pp);

    //////////////////////
    //   Start round 1  //
    //////////////////////

    // Generate the vanishing polys Z_j
    let z_polys = generate_vanishing_polys(&witness, &pp);

    // Generate the blinders
    let (r_blinders, s_blinders) = generate_blinders(&witness, rng);

    // Create blinded Z'_j, blinded V'_j
    let (blinded_z_polys, blinded_v_polys) = generate_blinded_z_v::<E>(&z_polys, &v_polys, &r_blinders, &s_blinders);

    // Generate the quotient polynomials and their blinded versions
    let (p_1_polys, p_2_polys) = generate_quotient_polys(&witness, &z_polys, &r_blinders, &v_polys, &s_blinders, &common_inputs, &pp);

    // Generate the blinded partial accumulators Z_1...j
    let partial_blinded_accs_polys = generate_partial_accumulators::<E>(&blinded_z_polys);

    // // Create x_j polys (before committing)
    let x_polys = generate_x_polys(&witness.subsets_indices, &blinded_z_polys, &pp);

    // Create commitments
    let round1proof = generate_commitments(&x_polys, &blinded_z_polys, &blinded_v_polys, &partial_blinded_accs_polys, &pp);

    // Get challenges
    let challenges = get_challenges(&round1proof, &common_inputs);


    //////////////////////
    //   Start round 2  //
    //////////////////////

    let now = Instant::now();
    println!("...Generating round 2 proof");

    // Compute p_j and publish
    let p_0_comm = g2_commit::<E>(&pp.g2_powers, &(&p_1_polys[0] + &(&p_2_polys[0] * challenges[0])));

    let mut p_nonzero_comm = vec!();
    p_nonzero_comm.resize(witness.subsets_indices.len() - 1, E::G1Affine::zero());

    p_nonzero_comm.par_iter_mut().enumerate().for_each(|(j, commit)| {
        *commit = g1_commit(&pp.poly_ck, &(&p_1_polys[j + 1] + &(&p_2_polys[j + 1] * challenges[j + 1])));
    });

    println!("......Took {:?}", now.elapsed());

    return Proof {
        round1proof,
        p_0_comm,
        p_nonzero_comm
    }
}
