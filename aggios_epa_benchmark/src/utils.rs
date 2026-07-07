// Contains miscellaneous functions used at some point or the other

use ark_ec::PairingEngine;
use ark_serialize::CanonicalSerialize;
use ark_std::{test_rng, rand::RngCore};

use rand::{distributions::Uniform, Rng, prelude::SliceRandom};
use std::time::Instant;
use std::{fs::File, io::Write};

use crate::structs::{Round1Proof, CommonInputs, AggiosTranscript, Proof};

// Concatenates a variable to a 'static byte string (to avoid having identical labels in the transcript)
// Since this uses Box::leak we are leaking memory, but since it will only be a few usize it is not dramatic
pub fn concat_to_static(base: &'static [u8], j: usize) -> &'static [u8] {
    let mut concat = Vec::from(base);
    concat.extend_from_slice(j.to_string().as_bytes());

    Box::leak(concat.into_boxed_slice())
}


pub fn readline() -> String {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).expect("Invalid input");
    return line;
}


// Given the size, return a random permutation
pub fn get_permutation<R: RngCore>(n: usize, rng: &mut R) -> Vec<usize> {
    let mut vec: Vec<usize> = (0..n).collect();
    let u: &mut [usize] = &mut vec[..];
    u.shuffle(rng);

    Vec::from(u)
}


// From a proof, (deterministically) generate challenges
// Used both by the prover and verifier
pub fn get_challenges<E:PairingEngine>(round1proof: &Round1Proof<E>, common_inputs: &CommonInputs<E>) -> Vec<E::Fr> {
    println!("...Getting challenges");
    let now = Instant::now();

    // Get k challenges
    let k = common_inputs.subsets_sizes.len();

    let mut transcript = AggiosTranscript::<E::Fr>::new();

    transcript.append_element(b"c_com", &common_inputs.c_comm);
    for j in 0..round1proof.x_comm.len() {
        transcript.append_element(concat_to_static(b"x_com", j), &round1proof.x_comm[j]);
    }

    transcript.append_element(b"z_0_comm", &round1proof.z_0_comm);
    for j in 0..round1proof.z_nonzero_comm.len() {
        transcript.append_element(concat_to_static(b"z_comm", j), &round1proof.z_nonzero_comm[j]);
    }

    for j in 0..round1proof.v_comm.len() {
        transcript.append_element(concat_to_static(b"v_comm", j), &round1proof.v_comm[j]);
    }

    for j in 0..round1proof.y_comm.len() {
        transcript.append_element(concat_to_static(b"y_comm", j), &round1proof.y_comm[j]);
    }

    // get challenges
    let mut challenges = vec!();
    for j in 0..k {
        challenges.push(transcript.get_and_append_challenge(concat_to_static(b"chi", j)));
    }

    println!("......Took {:?}", now.elapsed());
    challenges
}

fn save_vec<T: CanonicalSerialize>(v: &Vec<T>, file: &mut File) {
    let mut array_bytes = vec!();
    let size: u32 = v.len().try_into().unwrap();
    let size_bytes = size.to_be_bytes();
    file.write_all(&size_bytes).expect("error writing vector size");
    for element in v.iter() {
        element.serialize_uncompressed(&mut array_bytes).ok();
    }
    file.write_all(&array_bytes).expect("error during writing vector of commitments");
}


// Useful for accurate measuring of proof size
// For the poc we do not need the inverse function but is "just" reading the bytes
// Maybe some optimisation can be done by removing the size indicators (~5 bytes max)
#[allow(dead_code)]
pub fn save_proof<E: PairingEngine>(proof: &Proof<E>, path: &str) {
    let mut f = File::create(path).expect("unable to create file");
    // store vectors
    save_vec(&proof.round1proof.x_comm, &mut f);
    save_vec(&proof.round1proof.y_comm, &mut f);
    save_vec(&proof.round1proof.v_comm, &mut f);
    save_vec(&proof.p_nonzero_comm, &mut f);
    save_vec(&proof.round1proof.z_nonzero_comm, &mut f);

    // store single points
    let mut points_bytes = vec!();
    proof.round1proof.z_0_comm.serialize_uncompressed(&mut points_bytes).ok();
    proof.p_0_comm.serialize_uncompressed(&mut points_bytes).ok();
    f.write_all(&points_bytes).expect("error during writing of individual commitments");
}



// Given a number of voters and candidates, generate random votes
// Note that a candidate can receive 0 votes in which case we consider that there are k-1 candidates
pub fn get_random_votes(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut rng = test_rng();
    let random_permut = get_permutation(n, &mut rng);

    // separators are where we cut in the random permutation
    let range = Uniform::new(1, n - 1);
    let mut random_separators = (0..k-1).map(|_| rng.sample(&range)).collect::<Vec<usize>>();
    random_separators.sort_unstable();
    random_separators.dedup();
    random_separators.push(n);

    // println!("{:?}", random_separators);
    let mut subsets_indices = vec!();
    let mut previous_separator = 0;
    for separator in random_separators.iter() {
        // subset = random_permut[previous:separator]
        let mut subset = vec!();
        for i in previous_separator..*separator {
            subset.push(random_permut[i]);
        }
        subset.sort_unstable();
        subsets_indices.push(subset);
        previous_separator = *separator;
    }

    // Update k in the case where one candidate has 0 votes (thus we only vote on the other candidates)
    subsets_indices
}
