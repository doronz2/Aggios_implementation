use std::cmp::min;
use ark_ec::PairingEngine;
use ark_poly::{Polynomial, UVPolynomial, univariate::DensePolynomial};
use ark_std::{One, Zero};

// This file gives an O(n log n) division algorithm for polynomials
// assuming an O(n log n) multiplication algorithm for polys
// It relies on Hensel lift, as seen in eg https://people.csail.mit.edu/madhu/ST12/scribe/lect06.pdf
// More details in our paper


// Given `inverse` such that `inverse * poly = 1 mod X^deg`, return `new_inverse` such that `new_inverse * poly = 1 mod X^(2*deg)`
// More precisely, decomposing `inverse * poly` as `1 + c * X^deg` (`c` is easily extracted from the coefficient list),
// then `new_inverse = inverse - x^l (c * poly mod X^l)`
// For better performance, `poly` is reduced `mod X^2deg`, `c` is reduced `mod X^deg`
#[inline]
fn hensel_lift<E:PairingEngine>(poly: &DensePolynomial<E::Fr>, inverse: &DensePolynomial<E::Fr>, deg: usize) -> DensePolynomial<E::Fr> {
    let poly_mod_x2deg = DensePolynomial::from_coefficients_slice(&poly.coeffs[..min(2*deg, poly.coeffs.len())]);  // lowest degree that guarantees computing >=deg coefficient of C
    let one_plus_cxl = &poly_mod_x2deg * inverse;

    if one_plus_cxl.degree() < deg {
        // c = 0 thus we can simply return the inverse immediately and avoid out of range errors
        return inverse.clone()
    }
    let c = DensePolynomial::from_coefficients_slice(&one_plus_cxl.coeffs[deg..min(2*deg, one_plus_cxl.coeffs.len())]);  // we keep c of degree <= deg (above degree make computation slower and vanish under modulo anyways)

    // Ensure that the new_inverse has deg coefficients even if the leading ones are 0
    let mut new_inverse_coeffs = inverse.coeffs.clone();
    if new_inverse_coeffs.len() < deg {
        new_inverse_coeffs.resize(deg, E::Fr::zero());
    }

    let mut above_l_coeffs: Vec<E::Fr> = (inverse * &c).coeffs.iter().take(min(deg, inverse.coeffs.len() + &c.coeffs.len())).map(|&x| -x).collect();

    new_inverse_coeffs.append(&mut above_l_coeffs);
    return DensePolynomial::from_coefficients_slice(&new_inverse_coeffs);
}


// Finds the inverse of poly mod x^n.
// Starts by the trivial inverse of poly mod x, then hensel lift until the smallest power of 2 above n
// Then returns the result mod n
fn inverse_mod<E:PairingEngine>(poly: &DensePolynomial<E::Fr>, n: usize) -> DensePolynomial<E::Fr> {
    let mut current_inv = DensePolynomial::from_coefficients_slice(&[E::Fr::one() / poly.coeffs[0]]);
    let mut l = 1;

    while l < n {
        current_inv = hensel_lift::<E>(poly, &current_inv, l);
        l *= 2;
    }

    let max_coeff = min(current_inv.coeffs.len(), n + 1);

    // let inverse_mod_check = poly * &DensePolynomial::from_coefficients_slice(&current_inv.coeffs[..max_coeff]);
    // let inverse_check = DensePolynomial::from_coefficients_slice(&inverse_mod_check.coeffs[..min(n, inverse_mod_check.coeffs.len())]);
    // assert_eq!(inverse_check, DensePolynomial::from_coefficients_slice(&[E::Fr::one()]));

    return DensePolynomial::from_coefficients_slice(&current_inv.coeffs[..max_coeff]);
}


// Given a polynomial `a`, returns rev_{size}(a)
// panics if `size` is smaller than `a`'s size
fn rev<E:PairingEngine>(a: &DensePolynomial<E::Fr>, size: usize) -> DensePolynomial<E::Fr> {
    if a.coeffs.len() > size {
        panic!("Polynomial too big (size {}) to be reverted in size {}", a.coeffs.len(), size);
    } 

    let mut rev_coeffs = vec![E::Fr::zero(); size];
    rev_coeffs[..a.coeffs.len()].clone_from_slice(&a);
    return DensePolynomial::from_coefficients_slice(rev_coeffs.as_slice());
}


pub fn div_rem<E:PairingEngine>(a: &DensePolynomial<E::Fr>, b: &DensePolynomial<E::Fr>) -> (DensePolynomial<E::Fr>, DensePolynomial<E::Fr>) {
    if b.is_zero() {
        panic!("Cannot divide by 0");
    }

    if b.degree() > a.degree() {
        return (DensePolynomial::from_coefficients_slice(&[E::Fr::zero()]), a.clone());
    }

    let rev_a = rev::<E>(a, a.degree() + 1);
    let rev_b = rev::<E>(b, b.degree() + 1);

    let inversion_degree = a.degree() - b.degree() + 1;
    let rev_b_inv = inverse_mod::<E>(&rev_b, inversion_degree);

    let rev_q = DensePolynomial::from_coefficients_slice(&(&rev_b_inv * &rev_a).coeffs[..inversion_degree]);
    let q = DensePolynomial::from_coefficients_slice(&rev::<E>(&rev_q, inversion_degree).coeffs.as_slice());
    let r = a - &(b * &q);

    return (q, r);
}


// This function assumes that the division of a by b is exact, i.e. has no remainder.
pub fn poly_div<E:PairingEngine>(a: &DensePolynomial<E::Fr>, b: &DensePolynomial<E::Fr>) -> DensePolynomial<E::Fr> {
    if b.is_zero() {
        panic!("Cannot divide by 0");
    }

    // let degree = a.degree() - b.degree() + 1;
    // let inv_b = inverse_mod::<E>(&b, degree);

    // return DensePolynomial::from_coefficients_slice(&(&inv_b * a).coeffs[..degree]);

    let (q, r) = div_rem::<E>(a, b);

    if !r.is_zero() {
        panic!("ohnoes");
    }

    return q
}
