use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand};
use ark_poly::{UVPolynomial, univariate::DensePolynomial};
use ark_poly_commit::kzg10::{KZG10, Powers, VerifierKey, UniversalParams};
use ark_std::test_rng; // same rng all executions, practical for debugging


// Reduces full srs down to smaller srs for smaller polynomials
// Copied from Caulk, copied from arkworks library (where same function is private)
// Not super sure if useful but is not very long anyways
fn trim<E: PairingEngine, P: UVPolynomial<E::Fr>>(
    srs: &UniversalParams<E>,
    mut supported_degree: usize,
) -> (Powers<'static, E>, VerifierKey<E>) {
    if supported_degree == 1 {
        supported_degree += 1;
    }

    let powers_of_g = srs.powers_of_g[..=supported_degree].to_vec();
    let powers_of_gamma_g = (0..=supported_degree)
        .map(|i| srs.powers_of_gamma_g[&i])
        .collect();

    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };
    let vk = VerifierKey {
        g: srs.powers_of_g[0],
        gamma_g: srs.powers_of_gamma_g[&0],
        h: srs.h,
        beta_h: srs.beta_h,
        prepared_h: srs.prepared_h.clone(),
        prepared_beta_h: srs.prepared_beta_h.clone(),
    };
    (powers, vk)
}

pub fn get_powers<E:PairingEngine>(srs: &UniversalParams<E>, max_degree: usize) -> (Powers<'static, E>, Vec<E::G2Affine>) {
    let poly_ck: Powers<'static, E>;
    let poly_vk: VerifierKey<E>;  // We don't use poly_vk but it gives us g_2 which we use to generate the powers of g2
    let mut g2_powers: Vec<E::G2Affine> = Vec::new();

    let (poly_ck2, poly_vk2) = trim::<E, DensePolynomial<E::Fr>>(&srs, max_degree);
    poly_ck = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(poly_ck2.powers_of_g.into()),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(
            poly_ck2.powers_of_gamma_g.into(),
        ),
    };
    poly_vk = poly_vk2;

    // need some powers of g2 (adapted from Caulk)
    // arkworks setup doesn't give these powers but the setup does use a fixed
    // randomness to generate them. so we can generate powers of g2
    // directly.
    // (Provided we reset the rng)
    let rng = &mut test_rng();
    let beta = E::Fr::rand(rng);
    let mut temp = poly_vk.h;

    for _ in 0..poly_ck.powers_of_g.len() {
        g2_powers.push(temp);
        temp = temp.mul(beta).into_affine();
    }

    (poly_ck, g2_powers)
}

#[inline]
pub fn g1_commit<E:PairingEngine>(powers: &Powers<E>, poly: &DensePolynomial<E::Fr>) -> E::G1Affine {
    // println!("commit in g1 of degree {:?}", poly.degree());
    let (com, _) = KZG10::<E, _>::commit(powers, poly, None, None).unwrap();
    com.0
}

pub fn g1_commit_sparse<E:PairingEngine>(powers: &Powers<E>, poly_coeffs: &Vec<(usize, E::Fr)>) -> E::G1Affine {
    poly_coeffs.iter().map(|(i, coeff)| powers.powers_of_g[*i].mul(*coeff).into_affine()).sum()
}

// Taken from Caulk
// There is no native API for commit in G2
#[inline]
pub fn g2_commit<E:PairingEngine>(g2_powers: &[E::G2Affine], poly: &DensePolynomial<E::Fr>) -> E::G2Affine {
    // println!("Commit in g2 of degree {:?}", poly.degree());
    let poly_coeffs: Vec<<E::Fr as PrimeField>::BigInt> = poly.coeffs.iter().map(|&x| x.into_repr()).collect();
    let res = VariableBaseMSM::multi_scalar_mul(g2_powers, &poly_coeffs).into_affine();

    res
}

// Taken from Caulk
// There is no native API for commit in G2
#[inline]
pub fn g2_commit_sparse<E:PairingEngine>(g2_powers: &[E::G2Affine], poly_coeffs: &Vec<(usize, E::Fr)>) -> E::G2Affine {
    poly_coeffs.iter().map(|(i, coeff)| g2_powers[*i].mul(*coeff).into_affine()).sum()
}
