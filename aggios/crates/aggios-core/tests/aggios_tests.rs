//! Integration tests for the Aggios layer (spec section 18).

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;

use ark_bls12_381::Fr;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_std::UniformRand;
use rand::rngs::StdRng;
use rand::SeedableRng;

use aggios_core::artifacts::{RegistrationPostArtifact, TallyPostArtifact};
use aggios_core::benchmark::{
    run_benchmark, AssignmentStrategy, BenchmarkConfig, VoteDistributionKind,
};
use aggios_core::bls;
use aggios_core::election::{
    default_aggregators, template_candidates, ElectionParams, ElectionTemplate,
};
use aggios_core::epa_adapter::{self, get_or_create_srs, EpaProof, EpaPublicInput, EpaWitness};
use aggios_core::eqlog::{self, EqLogContext};
use aggios_core::labels::derive_election_labels;
use aggios_core::registration::{
    accept_registration, check_no_duplicate_voters, finalize_registration,
    validate_finalized_registration, RegisteredVoter, VoterKeys,
};
use aggios_core::tally::{
    build_and_prove_tally, global_tally, verify_aggregator_tally, TallyPost,
};

fn rng() -> StdRng {
    StdRng::seed_from_u64(7)
}

fn test_election(id: &str, num_candidates: usize) -> ElectionParams {
    let candidates = template_candidates(ElectionTemplate::Representative)
        .into_iter()
        .take(num_candidates)
        .collect();
    ElectionParams::new(
        id.to_string(),
        "Test election".into(),
        "test".into(),
        candidates,
        default_aggregators(),
        1000,
    )
}

// ---------------------------------------------------------------------------
// 1. BLS delegation
// ---------------------------------------------------------------------------

#[test]
fn bls_valid_signature_verifies_and_wrong_aggregator_fails() {
    let mut rng = rng();
    let keys = bls::SigningKeypair::generate(&mut rng);
    let sigma = bls::sign_delegation(&keys.sk, "e1", "A1");
    assert!(bls::verify_delegation(&sigma, &keys.pk, "e1", "A1"));
    assert!(!bls::verify_delegation(&sigma, &keys.pk, "e1", "A2"));
    assert!(!bls::verify_delegation(&sigma, &keys.pk, "e2", "A1"));
}

#[test]
fn bls_aggregate_signature_verifies_and_wrong_pk_fails() {
    let mut rng = rng();
    let keypairs: Vec<_> = (0..5)
        .map(|_| bls::SigningKeypair::generate(&mut rng))
        .collect();
    let sigmas: Vec<_> = keypairs
        .iter()
        .map(|k| bls::sign_delegation(&k.sk, "e1", "A1"))
        .collect();
    let pks: Vec<_> = keypairs.iter().map(|k| k.pk).collect();

    let agg_sigma = bls::aggregate_signatures(&sigmas);
    assert!(bls::verify_aggregate_delegation(&agg_sigma, &pks, "e1", "A1"));
    assert!(!bls::verify_aggregate_delegation(&agg_sigma, &pks, "e1", "A2"));

    // Swap one pk for a fresh key: aggregate must fail.
    let mut wrong_pks = pks.clone();
    wrong_pks[0] = bls::SigningKeypair::generate(&mut rng).pk;
    assert!(!bls::verify_aggregate_delegation(&agg_sigma, &wrong_pks, "e1", "A1"));
}

// ---------------------------------------------------------------------------
// 2. EqLog
// ---------------------------------------------------------------------------

#[test]
fn eqlog_valid_proof_verifies_and_tampering_fails() {
    let mut rng = rng();
    let bundle = get_or_create_srs(8).unwrap();
    let basis = bundle.lagrange_basis();
    let b = basis[3];

    let skv = Fr::rand(&mut rng);
    let tau = b.mul(skv).into_affine();
    let pkv = bls::g2_generator().mul(skv).into_affine();
    let context = EqLogContext {
        election_id: "e1".into(),
        aggregator_id: "A1".into(),
        voter_id: "v1".into(),
        local_index: 3,
        domain_size: 8,
    };

    let proof = eqlog::prove(&b, &tau, &pkv, &skv, &context, &mut rng);
    assert!(eqlog::verify(&b, &tau, &pkv, &proof, &context));

    // wrong τ
    let wrong_tau = b.mul(Fr::rand(&mut rng)).into_affine();
    assert!(!eqlog::verify(&b, &wrong_tau, &pkv, &proof, &context));

    // wrong pkv
    let wrong_pkv = bls::g2_generator().mul(Fr::rand(&mut rng)).into_affine();
    assert!(!eqlog::verify(&b, &tau, &wrong_pkv, &proof, &context));

    // wrong context
    let wrong_context = EqLogContext {
        local_index: 4,
        ..context.clone()
    };
    assert!(!eqlog::verify(&b, &tau, &pkv, &proof, &wrong_context));
}

// ---------------------------------------------------------------------------
// 4. EPA adapter smoke test
// ---------------------------------------------------------------------------

fn adapter_instance(
    sizes: Vec<usize>,
) -> (EpaPublicInput, EpaWitness, std::sync::Arc<epa_adapter::SrsBundle>) {
    let mut rng = rng();
    let n: usize = sizes.iter().sum();
    assert!(n.is_power_of_two());
    let bundle = get_or_create_srs(n).unwrap();

    // Random token values, arbitrary hash labels.
    let values: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    let mut partitions: Vec<Vec<usize>> = Vec::new();
    let mut next = 0usize;
    for &s in &sizes {
        partitions.push((next..next + s).collect());
        next += s;
    }

    // C_commit = Σ values[i] · B_i
    let basis = bundle.lagrange_basis();
    let mut acc = ark_bls12_381::G1Projective::default();
    for (i, v) in values.iter().enumerate() {
        acc += basis[i].mul(*v);
    }

    let labels: Vec<Fr> = (0..sizes.len())
        .map(|j| aggios_core::hash::hash_to_fr(b"TEST_LABEL", &[&(j as u64).to_le_bytes()]))
        .collect();

    let public_input = EpaPublicInput {
        election_id: "adapter-test".into(),
        aggregator_id: "A1".into(),
        domain_size: n,
        commitment_c: acc.into_affine(),
        labels,
        label_indices: EpaPublicInput::canonical_label_indices(sizes.len()),
        sizes,
        srs_ref: bundle.srs_ref.clone(),
    };
    let witness = EpaWitness {
        values_by_index: values,
        partition_indices: partitions,
    };
    (public_input, witness, bundle)
}

#[test]
fn adapter_prove_verify_and_tampering() {
    let (public_input, witness, bundle) = adapter_instance(vec![3, 2, 2, 1]);
    let result = epa_adapter::prove(&bundle, &public_input, &witness).unwrap();
    assert!(result.proof_size_bytes > 0);

    let verification = epa_adapter::verify(&bundle, &public_input, &result.proof).unwrap();
    assert!(verification.valid, "honest proof must verify");

    // Tampered size: swap two partition sizes.
    let mut tampered = public_input.clone();
    tampered.sizes = vec![2, 3, 2, 1];
    let v = epa_adapter::verify(&bundle, &tampered, &result.proof).unwrap();
    assert!(!v.valid, "tampered sizes must fail");

    // Tampered label index.
    let mut tampered = public_input.clone();
    tampered.label_indices = vec![1, 2, 3, 5];
    let v = epa_adapter::verify(&bundle, &tampered, &result.proof).unwrap();
    assert!(!v.valid, "tampered label must fail");

    // Tampered commitment.
    let mut tampered = public_input.clone();
    tampered.commitment_c = tampered
        .commitment_c
        .mul(Fr::from(2u64))
        .into_affine();
    let v = epa_adapter::verify(&bundle, &tampered, &result.proof).unwrap();
    assert!(!v.valid, "tampered commitment must fail");
}

#[test]
fn adapter_supports_zero_size_partitions_via_filtering() {
    // A candidate with zero votes: partition sizes contain a 0.
    let (public_input, witness, bundle) = adapter_instance(vec![5, 0, 2, 1]);
    let result = epa_adapter::prove(&bundle, &public_input, &witness).unwrap();
    let verification = epa_adapter::verify(&bundle, &public_input, &result.proof).unwrap();
    assert!(verification.valid);

    // Claiming the zero partition actually has size 1 must fail.
    let mut tampered = public_input.clone();
    tampered.sizes = vec![4, 1, 2, 1];
    let v = epa_adapter::verify(&bundle, &tampered, &result.proof).unwrap();
    assert!(!v.valid);
}

#[test]
fn adapter_single_nonempty_partition() {
    // Everyone in one partition (e.g. unanimous vote, no padding).
    let (public_input, witness, bundle) = adapter_instance(vec![8, 0, 0]);
    match epa_adapter::prove(&bundle, &public_input, &witness) {
        Ok(result) => {
            let verification =
                epa_adapter::verify(&bundle, &public_input, &result.proof).unwrap();
            assert!(verification.valid, "single-partition proof should verify");
        }
        Err(e) => panic!("single nonempty partition unsupported: {}", e),
    }
}

#[test]
fn adapter_proof_serialization_round_trip() {
    let (public_input, witness, bundle) = adapter_instance(vec![4, 2, 2]);
    let result = epa_adapter::prove(&bundle, &public_input, &witness).unwrap();

    let bytes = result.proof.to_bytes().unwrap();
    assert_eq!(bytes.len(), result.proof_size_bytes);
    let restored = EpaProof::from_bytes(&bytes).unwrap();
    let verification = epa_adapter::verify(&bundle, &public_input, &restored).unwrap();
    assert!(verification.valid, "deserialized proof must still verify");
}

// ---------------------------------------------------------------------------
// 5. Registration
// ---------------------------------------------------------------------------

struct DemoVoter {
    voter_id: String,
    keys: VoterKeys,
}

fn make_voters(n: usize, rng: &mut StdRng) -> Vec<DemoVoter> {
    (0..n)
        .map(|i| DemoVoter {
            voter_id: format!("voter-{}", i),
            keys: VoterKeys::generate(rng),
        })
        .collect()
}

fn register_all(
    election: &ElectionParams,
    aggregator_id: &str,
    voters: &[DemoVoter],
) -> Vec<RegisteredVoter> {
    voters
        .iter()
        .map(|v| {
            let sigma = v.keys.sign_delegation(&election.election_id, aggregator_id);
            accept_registration(
                &election.election_id,
                aggregator_id,
                &v.voter_id,
                &v.keys.signing.pk,
                &v.keys.pkv,
                &sigma,
                &v.keys.skv,
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn registration_valid_accepted_invalid_rejected() {
    let mut rng = rng();
    let election = test_election("reg-test", 3);
    let voters = make_voters(3, &mut rng);

    // Valid registration accepted.
    let registered = register_all(&election, "A1", &voters);
    assert_eq!(registered.len(), 3);

    // Invalid delegation (signed for A2, presented to A1) rejected.
    let bad_sigma = voters[0].keys.sign_delegation(&election.election_id, "A2");
    let res = accept_registration(
        &election.election_id,
        "A1",
        &voters[0].voter_id,
        &voters[0].keys.signing.pk,
        &voters[0].keys.pkv,
        &bad_sigma,
        &voters[0].keys.skv,
    );
    assert!(res.is_err());

    // skv not matching pkv rejected.
    let sigma = voters[0].keys.sign_delegation(&election.election_id, "A1");
    let res = accept_registration(
        &election.election_id,
        "A1",
        &voters[0].voter_id,
        &voters[0].keys.signing.pk,
        &voters[0].keys.pkv,
        &sigma,
        &Fr::rand(&mut rng),
    );
    assert!(res.is_err());
}

#[test]
fn registration_duplicate_across_aggregators_detected() {
    let mut rng = rng();
    let election = test_election("dup-test", 3);
    let voters = make_voters(2, &mut rng);

    let reg_a1 = register_all(&election, "A1", &voters);
    let reg_a2 = register_all(&election, "A2", &voters[..1]);

    let (post_a1, _) =
        finalize_registration(&election, "A1", &reg_a1, 0, &mut rng).unwrap();
    let (post_a2, _) =
        finalize_registration(&election, "A2", &reg_a2, 0, &mut rng).unwrap();

    let errors = check_no_duplicate_voters(&[&post_a1, &post_a2]);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("voter-0"));
}

#[test]
fn registration_post_validates_and_tampered_eqlog_rejected() {
    let mut rng = rng();
    let election = test_election("val-test", 3);
    let voters = make_voters(5, &mut rng);
    let registered = register_all(&election, "A1", &voters);
    let (mut post, _) =
        finalize_registration(&election, "A1", &registered, 0, &mut rng).unwrap();

    // Individual and aggregate BLS variants both pass.
    assert!(validate_finalized_registration(&election, &post, false)
        .unwrap()
        .ok());
    assert!(validate_finalized_registration(&election, &post, true)
        .unwrap()
        .ok());

    // Tamper with one EqLog response.
    post.voters[2].eqlog.z += Fr::from(1u64);
    let report = validate_finalized_registration(&election, &post, false).unwrap();
    assert!(!report.ok());
    assert!(report.errors.iter().any(|e| e.contains("EqLog")));
}

// ---------------------------------------------------------------------------
// 6-8. Small elections through the full pipeline
// ---------------------------------------------------------------------------

/// Runs a full single-aggregator flow and returns the post pair.
fn run_aggregator(
    election: &ElectionParams,
    aggregator_id: &str,
    voters: &[DemoVoter],
    votes: &HashMap<String, String>,
    rng: &mut StdRng,
) -> (aggios_core::registration::FinalizedRegistration, TallyPost) {
    let registered = register_all(election, aggregator_id, voters);
    let (finalized, _) =
        finalize_registration(election, aggregator_id, &registered, 0, rng).unwrap();
    let report = validate_finalized_registration(election, &finalized, false).unwrap();
    assert!(report.ok(), "registration validation failed: {:?}", report.errors);

    let labels = derive_election_labels(&election.election_id, &election.candidate_pairs());
    let post = build_and_prove_tally(election, &labels, &finalized, &registered, votes).unwrap();
    (finalized, post)
}

#[test]
fn small_election_9_voters_3_aggregators_3_candidates() {
    let mut rng = rng();
    let election = test_election("small-9", 3);
    let labels = derive_election_labels(&election.election_id, &election.candidate_pairs());
    let candidate_ids: Vec<String> =
        election.candidates.iter().map(|c| c.id.clone()).collect();

    // Deterministic votes: voter i of aggregator j votes candidate (i+j) % 3.
    // Expected per aggregator: one vote each -> global: 3 votes each.
    let mut posts = Vec::new();
    let mut verifications = Vec::new();
    for (j, aggregator_id) in ["A1", "A2", "A3"].iter().enumerate() {
        let voters: Vec<DemoVoter> = (0..3)
            .map(|i| DemoVoter {
                voter_id: format!("{}-v{}", aggregator_id, i),
                keys: VoterKeys::generate(&mut rng),
            })
            .collect();
        let votes: HashMap<String, String> = voters
            .iter()
            .enumerate()
            .map(|(i, v)| (v.voter_id.clone(), candidate_ids[(i + j) % 3].clone()))
            .collect();
        let (finalized, post) = run_aggregator(&election, aggregator_id, &voters, &votes, &mut rng);

        let verification = verify_aggregator_tally(&election, &labels, &finalized, &post);
        assert!(verification.valid, "EPA verification failed: {:?}", verification.errors);
        posts.push(post);
        verifications.push(verification);
    }

    let totals = global_tally(&election, &posts, &verifications);
    for id in &candidate_ids {
        assert_eq!(totals[id], 3, "candidate {} should have exactly 3 votes", id);
    }
    // Global tally counts only real candidate votes: 9 in total.
    assert_eq!(totals.values().sum::<usize>(), 9);
}

#[test]
fn padding_5_voters_domain_8_excludes_pad() {
    let mut rng = rng();
    let election = test_election("pad-test", 3);
    let labels = derive_election_labels(&election.election_id, &election.candidate_pairs());
    let voters = make_voters(5, &mut rng);
    let votes: HashMap<String, String> = voters
        .iter()
        .map(|v| (v.voter_id.clone(), election.candidates[0].id.clone()))
        .collect();

    let (finalized, post) = run_aggregator(&election, "A1", &voters, &votes, &mut rng);
    assert_eq!(finalized.domain_size, 8, "5 partitions + 5 voters -> domain 8");
    assert_eq!(finalized.pad_count, 3);
    assert_eq!(post.pad_count, 3);

    let verification = verify_aggregator_tally(&election, &labels, &finalized, &post);
    assert!(verification.valid, "{:?}", verification.errors);

    // Final tally excludes PAD.
    let totals = global_tally(&election, &[post.clone()], &[verification]);
    assert_eq!(totals.values().sum::<usize>(), 5);
    assert_eq!(totals[&election.candidates[0].id], 5);
}

#[test]
fn no_vote_registered_voter_goes_to_no_vote_partition() {
    let mut rng = rng();
    let election = test_election("novote-test", 3);
    let labels = derive_election_labels(&election.election_id, &election.candidate_pairs());
    let voters = make_voters(4, &mut rng);

    // Voter 3 registers but never votes.
    let votes: HashMap<String, String> = voters[..3]
        .iter()
        .map(|v| (v.voter_id.clone(), election.candidates[1].id.clone()))
        .collect();

    let (finalized, post) = run_aggregator(&election, "A1", &voters, &votes, &mut rng);
    assert_eq!(post.no_vote_count, 1);

    let verification = verify_aggregator_tally(&election, &labels, &finalized, &post);
    assert!(verification.valid, "{:?}", verification.errors);

    let totals = global_tally(&election, &[post.clone()], &[verification]);
    // NO_VOTE excluded from the final tally.
    assert_eq!(totals.values().sum::<usize>(), 3);
    assert_eq!(totals[&election.candidates[1].id], 3);
}

// ---------------------------------------------------------------------------
// 9. Serialization round-trips
// ---------------------------------------------------------------------------

#[test]
fn serialization_round_trips_and_verification_still_succeeds() {
    let mut rng = rng();
    let election = test_election("ser-test", 3);
    let labels = derive_election_labels(&election.election_id, &election.candidate_pairs());

    // Election params round-trip.
    let json = serde_json::to_string(&election).unwrap();
    let restored: ElectionParams = serde_json::from_str(&json).unwrap();
    assert_eq!(election, restored);

    let voters = make_voters(4, &mut rng);
    let votes: HashMap<String, String> = voters
        .iter()
        .enumerate()
        .map(|(i, v)| {
            (
                v.voter_id.clone(),
                election.candidates[i % 3].id.clone(),
            )
        })
        .collect();
    let (finalized, post) = run_aggregator(&election, "A2", &voters, &votes, &mut rng);

    // Registration post round-trip through the JSON artifact.
    let artifact = RegistrationPostArtifact::from_post(&finalized);
    let json = serde_json::to_string(&artifact).unwrap();
    let artifact2: RegistrationPostArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, artifact2);
    let finalized2 = artifact2.to_post().unwrap();
    assert!(validate_finalized_registration(&election, &finalized2, false)
        .unwrap()
        .ok());

    // Tally post (including EPA proof) round-trip through the JSON artifact,
    // then verification against the round-tripped registration post.
    let tally_artifact = TallyPostArtifact::from_post(&post);
    let json = serde_json::to_string(&tally_artifact).unwrap();
    let tally_artifact2: TallyPostArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(tally_artifact, tally_artifact2);
    let post2 = tally_artifact2.to_post().unwrap();

    let verification = verify_aggregator_tally(&election, &labels, &finalized2, &post2);
    assert!(verification.valid, "{:?}", verification.errors);
}

// ---------------------------------------------------------------------------
// 10-12. Benchmarks
// ---------------------------------------------------------------------------

#[test]
fn benchmark_n100_real_crypto_completes() {
    let config = BenchmarkConfig {
        voters: 100,
        aggregators: 3,
        template: ElectionTemplate::Representative,
        assignment: AssignmentStrategy::Uniform,
        vote_distribution: VoteDistributionKind::Uniform,
        seed: 42,
        real_crypto: true,
        ..Default::default()
    };
    let cancel = AtomicBool::new(false);
    let result = run_benchmark(&config, &|_e| {}, &cancel);
    assert!(result.success, "benchmark failed: {:?}", result.error);
    assert!(result.tally_matches_expected);
    assert_eq!(result.voter_count, 100);
    assert_eq!(
        result.candidate_tally.values().sum::<usize>(),
        100,
        "all 100 votes counted"
    );
    assert!(result.per_aggregator.iter().all(|a| a.verified));
}

/// N=1000 real crypto. Slow in debug builds; run with
/// `cargo test --release -- --ignored benchmark_n1000`.
#[test]
#[ignore]
fn benchmark_n1000_real_crypto_completes() {
    let config = BenchmarkConfig {
        voters: 1000,
        seed: 42,
        ..Default::default()
    };
    let cancel = AtomicBool::new(false);
    let result = run_benchmark(&config, &|_e| {}, &cancel);
    assert!(result.success, "benchmark failed: {:?}", result.error);
}

#[test]
fn benchmark_1e6_simulation_streams_without_storing_voters() {
    // 10^6 voters, simulation (counting-only) mode: must complete quickly
    // and must never materialize per-voter objects.
    let config = BenchmarkConfig {
        voters: 1_000_000,
        aggregators: 3,
        template: ElectionTemplate::CrimeReform,
        assignment: AssignmentStrategy::Skewed,
        vote_distribution: VoteDistributionKind::Skewed,
        seed: 42,
        real_crypto: false,
        ..Default::default()
    };
    let cancel = AtomicBool::new(false);
    let result = run_benchmark(&config, &|_e| {}, &cancel);
    assert!(result.success);
    assert!(result.mode.contains("NON-CRYPTOGRAPHIC"));
    assert_eq!(result.voters_per_aggregator.iter().sum::<usize>(), 1_000_000);
    // Skewed 80/15/5 assignment.
    assert!(result.voters_per_aggregator[0] > 750_000);
    assert_eq!(result.expected_tally.values().sum::<usize>(), 1_000_000);
}
