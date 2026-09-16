//! Served proofs resolve to the activity derived by full close validation.

use super::*;
use crate::chain::da::{tests::Fixture, *};
use commonware_clearing::bajillion::challenge::HigherEntryLookup;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

#[test]
fn served_account_and_entry_proofs_resolve_to_the_validated_activity() {
    deterministic::Runner::default().start(|context| async move {
        for (case, (outgoing, withdrawals)) in
            [(0, 0), (0, 2), (2, 2), (4, 3)].into_iter().enumerate()
        {
            let run = context.child(["empty", "withdrawals", "mixed", "entries"][case]);
            let prefix = format!("parity{case}");
            let mut fixture = Fixture::new(&run, &prefix, 8).await;
            let (ballot, _, prepared) = fixture
                .prepare(
                    outgoing,
                    withdrawals,
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await;
            let payer = fixture.active(0).public_key();
            let recipient = fixture.active(1).public_key();
            let expected_account = prepared
                .close()
                .rows
                .iter()
                .find(|row| row.account == payer)
                .map(|row| {
                    row.outgoing.as_ref().map_or((0, 0), |authorization| {
                        (
                            authorization.body().cumulative_debit(),
                            authorization.body().seq(),
                        )
                    })
                });
            let expected_entry = prepared
                .close()
                .out_vectors
                .iter()
                .find(|vector| vector.payer() == &payer)
                .and_then(|vector| {
                    vector
                        .entries()
                        .iter()
                        .find(|entry| entry.recipient == recipient)
                })
                .map(|entry| (entry.cumulative, entry.count))
                .unwrap_or((0, 0));
            fixture.candidate(ballot.clone(), prepared).await;
            let range = ballot.roots.activity_range(&ballot.context).unwrap();
            let lookup = EvidenceLookup::Account {
                epoch: 0,
                range,
                account: payer.clone(),
            };
            let response = serve(
                std::slice::from_ref(&fixture.lane),
                EvidenceRequest::new(ballot.deployment, lookup),
            )
            .await
            .unwrap();
            let EvidenceResponse::Served(Evidence::Account(actual)) = response else {
                panic!("account proof");
            };
            let (debit, change) = actual.resolve::<Sha256>(&range, &payer).unwrap();
            assert_eq!(change.is_some(), expected_account.is_some());
            assert_eq!(debit, expected_account.map_or(0, |expected| expected.0));
            assert_eq!(
                change.map(|change| change.terminal_seq()),
                expected_account.map(|expected| expected.1)
            );
            let lookup = EvidenceLookup::CommittedEntry {
                epoch: 0,
                range,
                payer: payer.clone(),
                recipient: recipient.clone(),
            };
            let response = serve(
                std::slice::from_ref(&fixture.lane),
                EvidenceRequest::new(ballot.deployment, lookup),
            )
            .await
            .unwrap();
            let EvidenceResponse::Served(Evidence::CommittedEntry(actual)) = response else {
                panic!("entry proof");
            };
            assert_eq!(
                matches!(&actual, HigherEntryLookup::Present { .. }),
                expected_account.is_some()
            );
            assert_eq!(
                actual
                    .resolve::<Sha256>(&range, &payer, &recipient)
                    .unwrap(),
                expected_entry
            );
            let mut wrong = range;
            wrong.head.root = Digest::from([0u8; 32]);
            let query = EvidenceRequest::new(
                ballot.deployment,
                EvidenceLookup::Account {
                    epoch: 0,
                    range: wrong,
                    account: fixture.active(0).public_key(),
                },
            );
            let response = serve(std::slice::from_ref(&fixture.lane), query).await;
            assert!(response.is_err());
        }
    });
}
