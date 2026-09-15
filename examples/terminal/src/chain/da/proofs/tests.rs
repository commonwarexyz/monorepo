//! Native metadata and on-demand proof reconstruction use the same certified leaves.

use super::*;
use crate::chain::da::{
    tests::{Fixture, sealer},
    *,
};
use commonware_clearing::bajillion::{challenge::AccountLookup, serve::Index};
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

#[test]
fn native_answers_match_prepared_account_and_vector_proofs() {
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
            let expected = Index::new(prepared.close());
            let payer = fixture.active(0).public_key();
            let recipient = fixture.active(1).public_key();
            let account = expected.account_lookup::<Sha256>(&payer).unwrap();
            let entry = expected
                .higher_entry_lookup::<Sha256>(&payer, &recipient)
                .unwrap();
            fixture.candidate(ballot.clone(), prepared).await;
            let (owner, _) =
                sealer(&context, &format!("unused{case}"), &fixture.lane.deployment).await;
            let heads = ballot.roots.logs();
            let lookup = EvidenceLookup::Account {
                epoch: 0,
                heads,
                account: payer.clone(),
            };
            let response = serve(
                &owner.db,
                std::slice::from_ref(&fixture.lane),
                EvidenceRequest::new(ballot.deployment, lookup),
            )
            .await
            .unwrap();
            let EvidenceResponse::Served(Evidence::Account(actual)) = response else {
                panic!("account proof");
            };
            assert_eq!(actual, account);
            let lookup = EvidenceLookup::CommittedEntry {
                epoch: 0,
                heads,
                payer,
                recipient,
            };
            let response = serve(
                &owner.db,
                std::slice::from_ref(&fixture.lane),
                EvidenceRequest::new(ballot.deployment, lookup),
            )
            .await
            .unwrap();
            let EvidenceResponse::Served(Evidence::CommittedEntry(actual)) = response else {
                panic!("entry proof");
            };
            assert_eq!(actual, entry);
            let lookup = EvidenceLookup::CloseEvidence {
                epoch: 0,
                batch_id: ballot.header.batch_id::<Sha256>(),
            };
            let response = serve(
                &owner.db,
                std::slice::from_ref(&fixture.lane),
                EvidenceRequest::new(ballot.deployment, lookup),
            )
            .await
            .unwrap();
            let EvidenceResponse::Served(Evidence::Close {
                header,
                context: restored,
                withdrawal_claims,
                ..
            }) = response
            else {
                panic!("complete native close");
            };
            assert_eq!(header, ballot.header);
            assert_eq!(restored, ballot.context);
            assert_eq!(withdrawal_claims.len(), withdrawals);
            let mut wrong = heads;
            wrong.activity.root = Digest::from([0u8; 32]);
            let query = EvidenceRequest::new(
                ballot.deployment,
                EvidenceLookup::Account {
                    epoch: 0,
                    heads: wrong,
                    account: fixture.active(0).public_key(),
                },
            );
            assert!(
                serve(&owner.db, std::slice::from_ref(&fixture.lane), query)
                    .await
                    .is_err()
            );
            if outgoing == 0 && withdrawals == 0 {
                assert!(matches!(account, AccountLookup::Absent(_)));
            }
        }
    });
}
