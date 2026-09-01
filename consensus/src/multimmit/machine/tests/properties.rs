//! Property tests over generated fault schedules.

use super::fixtures::{Harness, active_machine, digest, symbolic_nullification, threshold_share};
use crate::{
    Epochable as _,
    multimmit::{
        config::Role,
        machine::{
            capability::Capability,
            durability::{Change, DischargeKind, PersistDirective, Publication, SendRequest},
            input::Input,
            testing::{CapabilitiesExt as _, Drive as _, Until, VerifyJobExt as _, cohort},
        },
        types::{Artifact, ChainId, DaVote, TransactionBlockHeader},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::Sha256;
use proptest::{collection::vec as prop_vec, prelude::*};
use std::sync::Arc;

proptest! {
    #[test]
    fn send_batch_assigns_stable_distinct_vote_obligation_ids(count in 1usize..=8) {
        let machine = active_machine(Role::Observer);
        let genesis = machine.profile().protocol().genesis().tips()[0];
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(0),
            Height::new(1),
            genesis.digest(),
            digest(b"batched vote obligation"),
        )
        .unwrap();
        let vote = Arc::new(Artifact::DaVote(DaVote::new(
            header,
            threshold_share(0),
        )));
        let requests = (0..count)
            .map(|_| SendRequest::new(Participant::new(0), Arc::clone(&vote)))
            .collect::<Vec<_>>();
        let publication = Publication::Send(requests.into());
        let first = machine.discharges(&publication).unwrap();
        let second = machine.discharges(&publication).unwrap();

        prop_assert_eq!(&first, &second);
        prop_assert_eq!(first.len(), count);
        for (item, discharge) in first.iter().copied().enumerate() {
            let stable = discharge.item() == item as u32
                && matches!(discharge.until(), DischargeKind::VoteCertifiedAtLeast { .. });
            prop_assert!(stable);
        }
    }

    #[test]
    fn generated_nullification_suffix_advances_in_order(
        priorities in prop_vec(any::<u8>(), 1..=5),
    ) {
        let (mut machine, _) = Harness::observer().participants(6).start();
        let mut views = (1..=priorities.len())
            .map(|view| View::new(view as u64))
            .collect::<Vec<_>>();
        views.sort_unstable_by_key(|view| (priorities[view.get() as usize - 1], view.get()));
        let artifacts = views
            .into_iter()
            .map(|view| Artifact::Nullification(symbolic_nullification(&machine, view, 0)))
            .collect();
        let observed = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
        let [Capability::Verify(verification)] = observed.capabilities() else {
            return Err(TestCaseError::fail("missing verification job"));
        };
        let step = machine
            .step(Input::Verified(verification.all_valid()))
            .unwrap();
        let mut step = machine.settle(step, Until::CursorAdvance);
        let mut advanced = Vec::new();
        while let Some(job) = step.find(|effect| match effect {
            Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
            _ => None,
        }) {
            // Staging applies the transition, so each staged exit reports the view it entered.
            let advances = job
                .events()
                .iter()
                .filter(|event| matches!(event.change(), Change::ViewAdvanced { .. }))
                .count();
            prop_assert!(advances <= 1, "one barrier carries at most one exit");
            if advances == 1 {
                advanced.push(machine.inspect().view());
            }
            step = machine.persist(&job, Until::CursorAdvance);
        }
        prop_assert_eq!(
            advanced,
            (2..=priorities.len() + 1)
                .map(|view| View::new(view as u64))
                .collect::<Vec<_>>()
        );
        prop_assert_eq!(
            machine.inspect().view(),
            View::new(priorities.len() as u64 + 1)
        );
    }
}
