//! Candidate scalar labels and the internal NO_VOTE / PAD labels.
//!
//! For each real candidate j:
//!   w_j = hash_to_fr("AGGIOS_CANDIDATE_LABEL" || election_id || candidate_id || name)
//! Internal labels:
//!   w_no_vote = hash_to_fr("AGGIOS_NO_VOTE_LABEL" || election_id)
//!   w_pad     = hash_to_fr("AGGIOS_PAD_LABEL"     || election_id)
//!
//! All labels must be nonzero and pairwise distinct; on a zero or collision we
//! rehash with a counter.
//!
//! NOTE on the EPA black box: the existing EPA implementation identifies each
//! partition by a *domain element index* (its `vote_per_j: Vec<usize>`; the
//! label scalar inside the proof is ω^index). The Aggios-level hash labels
//! w_j below therefore bind candidate identities on the bulletin board, while
//! the EPA adapter deterministically maps partition position j to the EPA
//! label index j+1. Both are published, and validators recompute both.

use ark_bls12_381::Fr;
use ark_std::Zero;

use crate::hash::hash_to_fr;

pub const CANDIDATE_LABEL_SEP: &[u8] = b"AGGIOS_CANDIDATE_LABEL";
pub const NO_VOTE_LABEL_SEP: &[u8] = b"AGGIOS_NO_VOTE_LABEL";
pub const PAD_LABEL_SEP: &[u8] = b"AGGIOS_PAD_LABEL";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElectionLabels {
    /// One label per real candidate, in candidate display order.
    pub candidate_labels: Vec<Fr>,
    pub no_vote_label: Fr,
    pub pad_label: Fr,
}

impl ElectionLabels {
    /// Full deterministic partition label list:
    /// candidates in display order, then NO_VOTE, then PAD.
    pub fn partition_labels(&self) -> Vec<Fr> {
        let mut labels = self.candidate_labels.clone();
        labels.push(self.no_vote_label);
        labels.push(self.pad_label);
        labels
    }
}

/// Derive a label, rehashing with a counter until it is nonzero and not
/// already contained in `taken`.
fn derive_distinct(sep: &[u8], parts: &[&[u8]], taken: &[Fr]) -> Fr {
    let mut counter: u64 = 0;
    loop {
        let ctr_bytes = counter.to_le_bytes();
        let mut all_parts: Vec<&[u8]> = parts.to_vec();
        let ctr_slice: &[u8] = &ctr_bytes;
        // counter 0 hashes without a suffix so the common case matches the
        // plain derivation formula
        if counter > 0 {
            all_parts.push(ctr_slice);
        }
        let candidate = hash_to_fr(sep, &all_parts);
        if !candidate.is_zero() && !taken.contains(&candidate) {
            return candidate;
        }
        counter += 1;
    }
}

/// Derive all labels for an election. `candidates` is a list of
/// (candidate_id, display_name) in display order.
pub fn derive_election_labels(election_id: &str, candidates: &[(String, String)]) -> ElectionLabels {
    let mut taken: Vec<Fr> = Vec::new();

    let mut candidate_labels = Vec::with_capacity(candidates.len());
    for (candidate_id, display_name) in candidates {
        let w = derive_distinct(
            CANDIDATE_LABEL_SEP,
            &[
                election_id.as_bytes(),
                candidate_id.as_bytes(),
                display_name.as_bytes(),
            ],
            &taken,
        );
        taken.push(w);
        candidate_labels.push(w);
    }

    let no_vote_label = derive_distinct(NO_VOTE_LABEL_SEP, &[election_id.as_bytes()], &taken);
    taken.push(no_vote_label);

    let pad_label = derive_distinct(PAD_LABEL_SEP, &[election_id.as_bytes()], &taken);

    ElectionLabels {
        candidate_labels,
        no_vote_label,
        pad_label,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates() -> Vec<(String, String)> {
        vec![
            ("c0".into(), "Alice".into()),
            ("c1".into(), "Bob".into()),
            ("c2".into(), "Charlie".into()),
        ]
    }

    #[test]
    fn labels_are_deterministic() {
        let a = derive_election_labels("election-1", &candidates());
        let b = derive_election_labels("election-1", &candidates());
        assert_eq!(a, b);
    }

    #[test]
    fn labels_are_nonzero_and_distinct() {
        let labels = derive_election_labels("election-1", &candidates());
        let all = labels.partition_labels();
        for (i, w) in all.iter().enumerate() {
            assert!(!w.is_zero());
            for w2 in all.iter().skip(i + 1) {
                assert_ne!(w, w2);
            }
        }
    }

    #[test]
    fn labels_depend_on_election_id() {
        let a = derive_election_labels("election-1", &candidates());
        let b = derive_election_labels("election-2", &candidates());
        assert_ne!(a.candidate_labels[0], b.candidate_labels[0]);
        assert_ne!(a.no_vote_label, b.no_vote_label);
        assert_ne!(a.pad_label, b.pad_label);
    }
}
