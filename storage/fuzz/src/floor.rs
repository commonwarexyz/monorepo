//! QMDB floor policies drawn from fuzz input, and a partial oracle for the floor walks they drive.
//!
//! A [`Plan`] picks the policy one batch walks its floor with: one of the library policies, or
//! a scripted policy whose choice for each update depends only on the update's key and value, so
//! equivalent batches built along different paths decide identically.
//!
//! [`Recorder`] runs a plan as a [`Policy`] and records every decision. [`Recorder::check`]
//! checks the record and the floor the batch's commit operation records against the target's
//! model of the batch's post-write state, then replays the record into that model.
//!
//! The oracle checks the decisions against the live values and the [`Limits`] of a fixed plan,
//! and the floor against the decisions and the number of live keys.
//!
//! The model maps keys to values and does not track where each key's live update lies. So the
//! oracle cannot see a walk that passes an active update without deciding it when the floor still
//! ends where a correct walk could end, and it never checks that the floor lies at or below every
//! live update.
//!
//! Without the tip of the batch's writes, the oracle also cannot tell where a walk that decided
//! every live key should end, and it checks a [`Proportional`] walk only for a floor that
//! does not decrease and stays below the commit.
//!
//! Reopening a database rebuilds its state by replaying the log from the floor, so a target that
//! reopens and then compares every key with its model catches a floor that passed an update
//! still live at reopen. The batch root targets do so after their last commit, and the Store
//! target at every simulated failure.
//!
//! A target that prunes up to the floor without reopening notices a pruned live update only when
//! it later reads that key.

use arbitrary::Arbitrary;
use commonware_storage::{
    merkle::{Family, Location},
    qmdb::floor::{Bounded, Decision, Entry, Hold, Limits, Policy, Proportional},
};
use commonware_utils::sequence::FixedBytes;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Debug,
};

/// A limit that binds within a fuzzed batch, or one that never binds.
#[derive(Arbitrary, Clone, Copy, Debug)]
pub enum Limit {
    /// `n % 8` entries or `n % 32` skips.
    Small(u8),
    /// The type's maximum, so the walk's window ends at the tip.
    Huge,
}

impl Limit {
    fn entries(self) -> usize {
        match self {
            Self::Small(n) => usize::from(n % 8),
            Self::Huge => usize::MAX,
        }
    }

    fn skips(self) -> u64 {
        match self {
            Self::Small(n) => u64::from(n % 32),
            Self::Huge => u64::MAX,
        }
    }
}

/// What a scripted policy does with an update it decides.
#[derive(Arbitrary, Clone, Copy, Debug)]
pub enum Choice {
    /// Keep the update, which moves it to the tip.
    Keep,
    /// Write the target's replacement value for this seed.
    Replace(u8),
    /// Delete the update's key.
    Evict,
    /// End the walk at the update.
    Stop,
}

/// The floor policy for one batch.
#[derive(Arbitrary, Clone, Debug)]
pub enum Plan {
    /// The library's [`Proportional`] policy.
    Proportional,
    /// The library's [`Hold`] policy, which decides nothing.
    Hold,
    /// The library's [`Bounded`] policy, which keeps every update it reaches.
    Bounded {
        /// The most updates to keep.
        entries: Limit,
        /// The most inactive locations to pass.
        skips: Limit,
    },
    /// Decide each update with the choice its key, value, and `salt` hash to.
    Scripted {
        /// The most updates to decide.
        entries: Limit,
        /// The most inactive locations to pass.
        skips: Limit,
        /// Mixed into the hash, so different salts pick different choices for the same update.
        salt: u8,
        /// The choices the hash picks from.
        choices: [Choice; 4],
    },
}

/// What a policy did with a decided update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome<V> {
    /// Kept the update, which moves it to the tip.
    Keep,
    /// Wrote this value for the key at the tip.
    Replace(V),
    /// Deleted the key.
    Evict,
    /// Ended the walk at the update without spending an entry.
    Stop,
}

/// One call of [`Policy::decide`]: the entry it received and what the policy did with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decided<K, V> {
    /// The update's location.
    pub location: u64,
    /// The updated key.
    pub key: K,
    /// The update's value.
    pub value: V,
    /// What the policy did with the update.
    pub outcome: Outcome<V>,
}

/// Runs a [`Plan`] as a [`Policy`] and records every decision it makes.
pub struct Recorder<K, V> {
    plan: Plan,
    replacement: fn(u8) -> V,
    decided: Vec<Decided<K, V>>,
}

impl<K, V> Recorder<K, V> {
    /// Run `plan`. A [`Choice::Replace`] with `seed` writes `replacement(seed)`.
    pub fn new(plan: &Plan, replacement: fn(u8) -> V) -> Self {
        Self {
            plan: plan.clone(),
            replacement,
            decided: Vec::new(),
        }
    }
}

/// Hash the salt, key, and value into an index of a scripted choice table.
fn script_index(salt: u8, key: &[u8], value: &[u8]) -> usize {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in [salt].iter().chain(key).chain(value) {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
    }
    (hash % 4) as usize
}

impl<F: Family, K: Clone + AsRef<[u8]>, V: Clone + AsRef<[u8]>> Policy<F, K, V> for Recorder<K, V> {
    fn evicts(&self) -> bool {
        matches!(self.plan, Plan::Scripted { .. })
    }

    fn limits(&self, made_inactive: usize) -> Limits {
        match self.plan {
            Plan::Proportional => Policy::<F, K, V>::limits(&Proportional, made_inactive),
            Plan::Hold => Policy::<F, K, V>::limits(&Hold, made_inactive),
            Plan::Bounded { entries, skips } | Plan::Scripted { entries, skips, .. } => Limits {
                entries: entries.entries(),
                skips: skips.skips(),
            },
        }
    }

    fn decide<'a>(&mut self, entry: Entry<'a, F, K, V>) -> Decision<'a, V> {
        let location = *entry.location();
        let key = entry.key().clone();
        let value = entry.value().clone();
        let (outcome, decision) = match self.plan {
            Plan::Proportional => (
                Outcome::Keep,
                Policy::<F, K, V>::decide(&mut Proportional, entry),
            ),
            Plan::Hold => panic!("{:?} limits must never reach decide", self.plan),
            Plan::Bounded { entries, skips } => {
                let mut bounded = Bounded {
                    entries: entries.entries(),
                    skips: skips.skips(),
                };
                (
                    Outcome::Keep,
                    Policy::<F, K, V>::decide(&mut bounded, entry),
                )
            }
            Plan::Scripted { salt, choices, .. } => {
                match choices[script_index(salt, key.as_ref(), value.as_ref())] {
                    Choice::Keep => (Outcome::Keep, entry.keep()),
                    Choice::Replace(seed) => {
                        let replacement = (self.replacement)(seed);
                        (
                            Outcome::Replace(replacement.clone()),
                            entry.replace(replacement),
                        )
                    }
                    Choice::Evict => (Outcome::Evict, entry.evict().0),
                    Choice::Stop => (Outcome::Stop, entry.stop()),
                }
            }
        };
        self.decided.push(Decided {
            location,
            key,
            value,
            outcome,
        });
        decision
    }
}

impl<K, V> Recorder<K, V>
where
    K: Clone + Ord + Debug + AsRef<[u8]>,
    V: Clone + PartialEq + Debug + AsRef<[u8]>,
{
    /// Check the batch's floor walk and replay its decisions into `model`.
    ///
    /// `model` holds the batch's live keys and values after its writes and before its walk.
    /// `inherited` is the floor the batch walked from, `floor` is the floor its commit operation
    /// records, and `commit` is that operation's location.
    ///
    /// # Panics
    ///
    /// Panics if the record or the floor breaks a rule of the walk that the model can see.
    pub fn check<F: Family>(
        &self,
        model: &mut BTreeMap<K, V>,
        inherited: Location<F>,
        floor: Location<F>,
        commit: Location<F>,
    ) {
        let fixed = match self.plan {
            Plan::Proportional => None,
            Plan::Hold => Some((0, 0)),
            Plan::Bounded { entries, skips } | Plan::Scripted { entries, skips, .. } => {
                Some((entries.entries(), skips.skips()))
            }
        };

        // The walk hands out live updates with their post-write values, each key at most once,
        // in location order between the inherited floor and the commit. Stop ends it. Under
        // fixed limits it decides at most `entries` updates, and each lies no further past the
        // inherited floor than the earlier decisions and every skip could carry the walk.
        let mut keys = BTreeSet::new();
        let mut previous = None;
        for (index, decided) in self.decided.iter().enumerate() {
            assert_eq!(
                model.get(&decided.key),
                Some(&decided.value),
                "decided update is not its key's live value: {decided:?}"
            );
            assert!(keys.insert(&decided.key), "key decided twice: {decided:?}");
            assert!(
                *inherited <= decided.location && decided.location < *commit,
                "decided location outside [{inherited}, {commit}): {decided:?}"
            );
            assert!(
                previous.is_none_or(|previous| previous < decided.location),
                "decisions out of location order: {decided:?}"
            );
            previous = Some(decided.location);
            if let Some((_, skips)) = fixed {
                assert!(
                    decided.location - *inherited <= (index as u64).saturating_add(skips),
                    "decision {index} lies past the skips from {inherited}: {decided:?}"
                );
            }
            if decided.outcome == Outcome::Stop {
                assert_eq!(index + 1, self.decided.len(), "walk continued past Stop");
            }
        }
        if let Some((entries, _)) = fixed {
            assert!(
                self.decided.len() <= entries,
                "decided {} updates with {entries} entries",
                self.decided.len()
            );
        }
        let live = model.len();
        let spent = self
            .decided
            .iter()
            .filter(|decided| decided.outcome != Outcome::Stop)
            .count();

        for decided in &self.decided {
            match &decided.outcome {
                Outcome::Replace(value) => {
                    model.insert(decided.key.clone(), value.clone());
                }
                Outcome::Evict => {
                    model.remove(&decided.key);
                }
                Outcome::Keep | Outcome::Stop => {}
            }
        }

        // The floor never decreases. When the final state is empty, the commit operation records
        // its own location as the floor. Otherwise every live update lies at or above the floor,
        // so the floor stays below the commit.
        assert!(
            inherited <= floor,
            "floor decreased: {inherited} -> {floor}"
        );
        if model.is_empty() {
            assert_eq!(floor, commit, "empty state's floor is not at its commit");
            return;
        }
        assert!(
            floor < commit,
            "floor {floor} reached commit {commit} with live keys"
        );
        let Some((entries, skips)) = fixed else {
            return;
        };

        // Each location the walk passes costs an entry or a skip. The commit operation records
        // the floor at a Stop, or one past the last decision when the entries ran out, or at the
        // inherited floor when there were no entries. With entries left, the walk ended by
        // spending every skip or by deciding every key live after the writes.
        let advanced = *floor - *inherited;
        let budget = (spent as u64).saturating_add(skips);
        assert!(
            advanced <= budget,
            "floor advanced {advanced} with {spent} decisions and {skips} skips"
        );
        match self.decided.last() {
            Some(last) if last.outcome == Outcome::Stop => {
                assert_eq!(*floor, last.location, "floor is not at the Stop");
            }
            last if spent == entries => assert_eq!(
                *floor,
                last.map_or(*inherited, |last| last.location + 1),
                "floor is not where the entries ran out"
            ),
            last => {
                assert!(
                    advanced == budget || self.decided.len() == live,
                    "walk with entries left advanced {advanced} of {budget} and decided {} of {live} live keys",
                    self.decided.len()
                );
                if let Some(last) = last {
                    assert!(*floor > last.location, "floor is not past its decisions");
                }
            }
        }
    }

    /// Check that this walk made the same decisions as `original`, a walk of the same batch built
    /// along another path.
    pub fn assert_same_walk(&self, original: &Self) {
        assert_eq!(
            self.decided, original.decided,
            "floor walk depended on the batch's path"
        );
    }
}

impl<const KN: usize, const VN: usize> Recorder<FixedBytes<KN>, FixedBytes<VN>> {
    /// [Check](Self::check) the walk against `state`, the live keys and values after the batch's
    /// writes in raw bytes, and return that state after the walk's decisions.
    pub fn check_raw<F: Family>(
        &self,
        state: impl IntoIterator<Item = ([u8; KN], [u8; VN])>,
        inherited: Location<F>,
        floor: Location<F>,
        commit: Location<F>,
    ) -> HashMap<[u8; KN], [u8; VN]> {
        let mut model = state
            .into_iter()
            .map(|(key, value)| (FixedBytes::new(key), FixedBytes::new(value)))
            .collect();
        self.check(&mut model, inherited, floor, commit);
        model
            .into_iter()
            .map(|(key, value)| {
                let key = key.as_ref().try_into().expect("fixed width");
                (key, value.as_ref().try_into().expect("fixed width"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_storage::merkle::mmr;

    type Bytes = Vec<u8>;

    fn at(n: u64) -> Location<mmr::Family> {
        Location::new(n)
    }

    /// A recorder of `plan` that made `decided`, where each decision names its location and its
    /// key, whose live value equals the key.
    fn recorder(plan: Plan, decided: &[(u64, &[u8], Outcome<Bytes>)]) -> Recorder<Bytes, Bytes> {
        Recorder {
            plan,
            replacement: |seed| vec![seed],
            decided: decided
                .iter()
                .map(|(location, key, outcome)| Decided {
                    location: *location,
                    key: key.to_vec(),
                    value: key.to_vec(),
                    outcome: outcome.clone(),
                })
                .collect(),
        }
    }

    /// Live keys whose values equal the keys.
    fn model(keys: &[&[u8]]) -> BTreeMap<Bytes, Bytes> {
        keys.iter()
            .map(|key| (key.to_vec(), key.to_vec()))
            .collect()
    }

    fn scripted(entries: Limit, skips: Limit) -> Plan {
        Plan::Scripted {
            entries,
            skips,
            salt: 0,
            choices: [Choice::Keep; 4],
        }
    }

    const ONE: Limit = Limit::Small(1);

    /// Legal walks pass: a batch whose writes delete the last key under zero entries, a walk that
    /// spends its skips before the first live update, and a walk that runs out of entries.
    #[test]
    fn check_accepts_legal_walks() {
        // A@1 and the commit at 2 with floor 0; the batch deletes A at 3 and commits at 4.
        let mut empty = model(&[]);
        recorder(Plan::Hold, &[]).check(&mut empty, at(0), at(4), at(4));

        // A@5 lies beyond three skips from floor 0.
        let bounded = Plan::Bounded {
            entries: ONE,
            skips: Limit::Small(3),
        };
        recorder(bounded, &[]).check(&mut model(&[b"A"]), at(0), at(3), at(7));

        // A@1, B@2, and the commit at 3 with floor 0; keeping A spends the only entry.
        let bounded = Plan::Bounded {
            entries: ONE,
            skips: Limit::Huge,
        };
        let mut live = model(&[b"A", b"B"]);
        recorder(bounded, &[(1, b"A", Outcome::Keep)]).check(&mut live, at(0), at(2), at(5));
        assert_eq!(live, model(&[b"A", b"B"]));
    }

    /// Evictions that empty the state still spend entries.
    #[test]
    #[should_panic(expected = "decided 2 updates with 1 entries")]
    fn check_rejects_decisions_past_entries_in_empty_state() {
        let decided = recorder(
            scripted(ONE, Limit::Huge),
            &[(1, b"A", Outcome::Evict), (2, b"B", Outcome::Evict)],
        );
        decided.check(&mut model(&[b"A", b"B"]), at(0), at(6), at(6));
    }

    /// A walk with an entry and unbounded skips decides a live key.
    #[test]
    #[should_panic(expected = "walk with entries left advanced 0")]
    fn check_rejects_walk_ending_at_inherited_floor() {
        let bounded = Plan::Bounded {
            entries: ONE,
            skips: Limit::Huge,
        };
        recorder(bounded, &[]).check(&mut model(&[b"A", b"B"]), at(0), at(0), at(4));
    }

    /// A walk with entries left that passes live keys without deciding them spends every skip.
    #[test]
    #[should_panic(expected = "walk with entries left advanced 2")]
    fn check_rejects_floor_past_undecided_keys() {
        let bounded = Plan::Bounded {
            entries: ONE,
            skips: Limit::Huge,
        };
        recorder(bounded, &[]).check(&mut model(&[b"A", b"B"]), at(0), at(2), at(4));
    }

    /// Evicting the last key empties the state, so the commit operation records its own location.
    #[test]
    #[should_panic(expected = "empty state's floor is not at its commit")]
    fn check_rejects_ignored_evict() {
        recorder(
            scripted(Limit::Huge, Limit::Huge),
            &[(1, b"A", Outcome::Evict)],
        )
        .check(&mut model(&[b"A"]), at(0), at(3), at(4));
    }

    /// Stop ends the walk.
    #[test]
    #[should_panic(expected = "walk continued past Stop")]
    fn check_rejects_decision_after_stop() {
        let decided = recorder(
            scripted(Limit::Huge, Limit::Huge),
            &[(1, b"A", Outcome::Stop), (2, b"B", Outcome::Keep)],
        );
        decided.check(&mut model(&[b"A", b"B"]), at(0), at(3), at(5));
    }

    /// Stop leaves the floor at the stopped update.
    #[test]
    #[should_panic(expected = "floor is not at the Stop")]
    fn check_rejects_floor_past_stop() {
        recorder(
            scripted(Limit::Huge, Limit::Huge),
            &[(2, b"A", Outcome::Stop)],
        )
        .check(&mut model(&[b"A"]), at(0), at(3), at(4));
    }
}
