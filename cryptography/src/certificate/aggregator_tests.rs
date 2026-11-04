//! Shared tests for [`Aggregator`] implementations.

use super::{Aggregator, AssemblyError, Attestation, Item, Scheme, Subject, Term, Verifier};
use crate::sha256::Digest as Sha256Digest;
use bytes::Bytes;
use commonware_codec::{Decode, Encode, types::lazy::Lazy};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::{NZUsize, Participant, non_empty, test_rng};

type D = Sha256Digest;

/// Returns `terms` with `known[i].1` attached to term `known[i].0`.
fn with_known<'a, S: Scheme>(
    terms: &[Term<'a, S, D>],
    known: &[(usize, &'a Attestation<S>)],
) -> Vec<Term<'a, S, D>> {
    let mut terms = terms.to_vec();
    for (index, attestation) in known {
        terms[*index].known = Some(*attestation);
    }
    terms
}

/// Returns an attestation signature that fails to decode.
pub(crate) fn malformed<S: Scheme>() -> Lazy<S::Signature> {
    Lazy::deferred(&mut Bytes::from_static(&[0u8]), ())
}

/// Signing schemes, a verifier, and distinct subjects for one [`Aggregator`].
pub(crate) struct Suite<'s, S, T> {
    /// Signing schemes of at least three participants.
    pub(crate) schemes: &'s [S],
    /// A verifier over the same participants.
    pub(crate) verifier: &'s S,
    /// Returns subject `i`. Distinct indices give distinct subjects, all signable together.
    pub(crate) subject: fn(usize) -> T,
    /// Whether signatures are unique and aggregates subtract known attestations.
    pub(crate) unique: bool,
}

impl<S, T> Suite<'_, S, T>
where
    S: Aggregator + for<'a> Verifier<Subject<'a, D> = T>,
    T: Subject,
{
    /// Runs every shared test.
    pub(crate) fn run(&self) {
        assert!(self.schemes.len() >= 3);
        self.valid();
        self.mixed();
        self.discharge();
        self.codec();
        self.assembly_errors();
        self.empty();
    }

    fn sign(&self, signer: usize, subject: usize) -> Attestation<S> {
        self.schemes[signer]
            .sign::<D>((self.subject)(subject))
            .expect("signer must sign")
    }

    /// Returns one attestation per signer, signer `i` signing subject `i`.
    fn attestations(&self) -> Vec<Attestation<S>> {
        (0..self.schemes.len()).map(|i| self.sign(i, i)).collect()
    }

    fn terms<'a>(&self, attestations: &'a [Attestation<S>]) -> Vec<Term<'a, S, D>> {
        attestations
            .iter()
            .enumerate()
            .map(|(i, attestation)| Term {
                signer: attestation.signer,
                subject: (self.subject)(i),
                known: None,
            })
            .collect()
    }

    fn aggregate<'a>(
        &self,
        attestations: impl IntoIterator<Item = &'a Attestation<S>>,
    ) -> S::Aggregate
    where
        S: 'a,
    {
        self.verifier
            .aggregate(non_empty![@attestations])
            .expect("aggregate must assemble")
    }

    fn verify(&self, items: &[Item<'_, '_, S, D>], strategy: &impl Strategy) -> Vec<bool> {
        self.verifier
            .verify_aggregates(&mut test_rng(), items, strategy)
    }

    fn verify_one(&self, terms: &[Term<'_, S, D>], aggregate: &S::Aggregate) -> bool {
        let verdict =
            self.verifier
                .verify_aggregate(&mut test_rng(), terms, aggregate, &Sequential);
        assert_eq!(
            self.verify(&[Item::Aggregate { terms, aggregate }], &Sequential),
            vec![verdict]
        );
        verdict
    }

    /// Aggregates over every signer, over one signer, and verified by a signer all pass.
    fn valid(&self) {
        let attestations = self.attestations();
        let terms = self.terms(&attestations);
        let aggregate = self.aggregate(&attestations);
        assert!(self.verify_one(&terms, &aggregate));
        assert!(self.schemes[0].verify_aggregate(&mut test_rng(), &terms, &aggregate, &Sequential));

        let single = self.aggregate(&attestations[1..2]);
        assert!(self.verify_one(&terms[1..2], &single));

        // Additive aggregates do not depend on term order, while lists do.
        let mut reversed = terms.clone();
        reversed.reverse();
        assert_eq!(self.verify_one(&reversed, &aggregate), self.unique);
    }

    /// A batch mixing valid and invalid attestations and aggregates returns each item's verdict.
    fn mixed(&self) {
        let n = self.schemes.len();
        let attestations = self.attestations();
        let terms = self.terms(&attestations);
        let aggregate = self.aggregate(&attestations);
        let single = self.aggregate(&attestations[1..2]);

        let mut swapped = terms.clone();
        swapped[1].subject = (self.subject)(n);
        let mut unknown = terms.clone();
        unknown[0].signer = Participant::from_usize(n);
        let duplicate = vec![
            terms[0].clone(),
            Term {
                signer: terms[0].signer,
                subject: (self.subject)(1),
                known: None,
            },
        ];
        let pair = self.aggregate(&attestations[..2]);
        let outsider = Attestation {
            signer: Participant::from_usize(n),
            signature: attestations[0].signature.clone(),
        };

        let items = [
            Item::Attestation {
                subject: (self.subject)(0),
                attestation: &attestations[0],
            },
            Item::Attestation {
                subject: (self.subject)(1),
                attestation: &attestations[0],
            },
            Item::Aggregate {
                terms: &terms,
                aggregate: &aggregate,
            },
            Item::Aggregate {
                terms: &swapped,
                aggregate: &aggregate,
            },
            Item::Aggregate {
                terms: &unknown,
                aggregate: &aggregate,
            },
            Item::Aggregate {
                terms: &duplicate,
                aggregate: &pair,
            },
            Item::Aggregate {
                terms: &[],
                aggregate: &single,
            },
            Item::Attestation {
                subject: (self.subject)(0),
                attestation: &outsider,
            },
            Item::Aggregate {
                terms: &terms[1..2],
                aggregate: &single,
            },
            Item::Aggregate {
                terms: &terms[..2],
                aggregate: &aggregate,
            },
        ];
        let expected = vec![
            true, false, true, false, false, false, false, false, true, false,
        ];
        assert_eq!(self.verify(&items, &Sequential), expected);
        let rayon = Rayon::new(NZUsize!(4)).unwrap();
        assert_eq!(self.verify(&items, &rayon), expected);

        // Items keep their verdicts in any order.
        let reversed: Vec<_> = items.iter().rev().cloned().collect();
        let mut expected_reversed = expected;
        expected_reversed.reverse();
        assert_eq!(self.verify(&reversed, &Sequential), expected_reversed);

        // A malformed attestation signature fails only its item.
        let malformed = Attestation {
            signer: attestations[0].signer,
            signature: malformed::<S>(),
        };
        assert_eq!(
            self.verify(
                &[
                    Item::Attestation {
                        subject: (self.subject)(0),
                        attestation: &malformed,
                    },
                    items[0].clone(),
                ],
                &Sequential,
            ),
            vec![false, true]
        );
    }

    /// Known attestations discharge terms only when they are the terms' signatures.
    fn discharge(&self) {
        let n = self.schemes.len();
        let attestations = self.attestations();
        let terms = self.terms(&attestations);
        let aggregate = self.aggregate(&attestations);

        // Some or all terms known.
        let some = with_known(&terms, &[(0, &attestations[0]), (2, &attestations[2])]);
        assert!(self.verify_one(&some, &aggregate));
        let all: Vec<_> = (0..n).map(|i| (i, &attestations[i])).collect();
        let all = with_known(&terms, &all);
        assert!(self.verify_one(&all, &aggregate));

        // A known signature by the right signer over another subject never discharges the term.
        // Lists verify the listed signature instead, which is valid here.
        let other = self.sign(0, n + 1);
        assert_eq!(
            self.verify_one(&with_known(&terms, &[(0, &other)]), &aggregate),
            !self.unique
        );

        // A forged signature in the aggregate fails whether its own term or another is known.
        let mut forged: Vec<_> = attestations.iter().collect();
        forged[0] = &other;
        let forged = self.aggregate(forged);
        assert!(!self.verify_one(&with_known(&terms, &[(0, &attestations[0])]), &forged));
        assert!(!self.verify_one(&with_known(&terms, &[(1, &attestations[1])]), &forged));
        assert!(!self.verify_one(
            &with_known(&terms, &[(0, &other)]),
            &self.aggregate(&attestations[1..2])
        ));

        // A known attestation by another signer, or a malformed one, fails the item.
        assert!(!self.verify_one(&with_known(&terms, &[(0, &attestations[1])]), &aggregate));
        let malformed = Attestation {
            signer: attestations[0].signer,
            signature: malformed::<S>(),
        };
        assert!(!self.verify_one(&with_known(&terms, &[(0, &malformed)]), &aggregate));

        // An aggregate missing a known term fails.
        let partial = self.aggregate(&attestations[1..]);
        assert!(!self.verify_one(&all, &partial));

        // A failing item with known terms does not fail its neighbors.
        let known_forged = with_known(&terms, &[(0, &attestations[0])]);
        assert_eq!(
            self.verify(
                &[
                    Item::Aggregate {
                        terms: &known_forged,
                        aggregate: &forged,
                    },
                    Item::Aggregate {
                        terms: &some,
                        aggregate: &aggregate,
                    },
                    Item::Aggregate {
                        terms: &all,
                        aggregate: &aggregate,
                    },
                ],
                &Sequential,
            ),
            vec![false, true, true]
        );
    }

    /// Aggregates round trip through their codec within the advertised bounds.
    fn codec(&self) {
        let n = self.schemes.len();
        let attestations = self.attestations();
        let terms = self.terms(&attestations);
        let mut previous = 0;
        for count in 1..=n {
            let bound = u32::try_from(count).unwrap();
            let aggregate = self.aggregate(&attestations[..count]);
            let encoded = aggregate.encode();
            let max = S::max_aggregate_size(bound);
            assert!(encoded.len() <= max);
            assert!(max >= previous);
            previous = max;

            let decoded =
                S::Aggregate::decode_cfg(encoded.clone(), &S::aggregate_codec_config(bound))
                    .unwrap();
            assert_eq!(decoded, aggregate);
            assert!(self.verify_one(&terms[..count], &decoded));

            // Lists bound their length by the number of terms.
            if !self.unique {
                assert!(
                    S::Aggregate::decode_cfg(encoded, &S::aggregate_codec_config(bound - 1))
                        .is_err()
                );
            }
        }
    }

    /// Aggregation rejects unknown and duplicate signers and malformed signatures.
    fn assembly_errors(&self) {
        let n = self.schemes.len();
        let attestations = self.attestations();
        let unknown = Attestation {
            signer: Participant::from_usize(n),
            signature: attestations[0].signature.clone(),
        };
        assert_eq!(
            self.verifier
                .aggregate(non_empty![&attestations[0], &unknown]),
            Err(AssemblyError::UnknownSigner(unknown.signer))
        );
        assert_eq!(
            self.verifier.aggregate(non_empty![
                &attestations[1],
                &attestations[0],
                &attestations[1]
            ]),
            Err(AssemblyError::DuplicateSigner(attestations[1].signer))
        );
        let malformed = Attestation {
            signer: attestations[2].signer,
            signature: malformed::<S>(),
        };
        assert_eq!(
            self.verifier
                .aggregate(non_empty![&attestations[0], &malformed]),
            Err(AssemblyError::MalformedSignature(malformed.signer))
        );
    }

    /// An empty batch has no verdicts.
    fn empty(&self) {
        assert!(self.verify(&[], &Sequential).is_empty());
    }
}
