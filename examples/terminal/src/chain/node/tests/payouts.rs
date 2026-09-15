use super::*;
use crate::protocol::{accounts, deployment, wallets};
use commonware_clearing::bajillion::boundary::{
    DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch,
};
use commonware_runtime::Runner as _;
use std::num::NonZeroU64;

#[test]
fn certifier_quorum_with_withdrawal_needs_no_proof_holder() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let verifier = protocol.verifier();
        let committee = committee().unwrap();
        let quorum = committee.quorum();
        let accounts = accounts();
        let wallet = wallets().remove(0);
        let genesis = protocol.fixture_genesis(&accounts).unwrap();
        let request = SignedWithdrawal::sign(
            deployment(),
            genesis.root().digest,
            wallet.public_key().encode(),
            WithdrawalAction::Amount(NonZeroU64::MIN),
            50,
            wallet.signer(),
        );
        let registration = protocol
            .registration(
                0,
                DepositBatch::empty(),
                WithdrawalBatch::new(vec![request]).unwrap(),
                accounts.iter().map(|account| account.balance).sum(),
            )
            .unwrap();
        let prepared = protocol.prepare(registration, Vec::new()).unwrap();
        let expected = protocol
            .fixture_complete(&accounts, &[], prepared.clone(), 42_000)
            .unwrap();
        assert_eq!(expected.withdrawal_total, 1);
        let proposal = Dealing {
            deployment: protocol.deployment(),
            epoch: 0,
            context: prepared.context().clone(),
            bytes: prepared.encoded().clone(),
        }
        .id();
        assert_eq!(*expected.roots.proposal.digest(), proposal);

        let operator_key = PrivateKey::from_seed(42_100).public_key();
        let validator_keys = (0..committee.members().len())
            .map(|index| PrivateKey::from_seed(42_101 + index as u64).public_key())
            .collect::<Vec<_>>();
        let mut peers = validator_keys.clone();
        peers.push(operator_key.clone());
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            NetConfig {
                max_size: 4 * 1024 * 1024,
                max_peers_per_set: NZUsize!(peers.len()),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            peers,
        )
        .await;
        network.start();
        let quota = Quota::per_second(NZU32!(128));
        let operator_channel = oracle
            .control(operator_key.clone())
            .register(0, quota)
            .await
            .unwrap();
        let mut validator_channels = Vec::new();
        for key in &validator_keys {
            validator_channels.push(
                oracle
                    .control(key.clone())
                    .register(0, quota)
                    .await
                    .unwrap(),
            );
        }
        let link = Link {
            latency: Duration::from_millis(1),
            jitter: Duration::ZERO,
            success_rate: probability!(1.0),
        };
        for key in &validator_keys {
            oracle
                .add_link(operator_key.clone(), key.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(key.clone(), operator_key.clone(), link.clone())
                .await
                .unwrap();
        }

        let (certifier, mailbox) = Certifier::new(
            context.child("certifier"),
            Config {
                verifier: verifier.clone(),
                chain: Stub(Vec::new()),
                mailbox_size: NZUsize!(16),
            },
        );
        certifier.start(operator_channel);
        let routes = validator_keys
            .iter()
            .enumerate()
            .map(|(index, peer)| Route {
                participant: dealt_participant(index).unwrap(),
                peer: peer.clone(),
            })
            .collect::<Vec<_>>();
        let certify = context
            .child("certify")
            .spawn(move |_| async move { mailbox.certify(prepared, routes).await });

        for channel in &mut validator_channels {
            let (from, bytes) = channel.1.recv().await.unwrap();
            assert_eq!(from, operator_key);
            let DaMessage::Dealing(dealing) = DaMessage::decode(bytes).unwrap() else {
                panic!("certifier disseminated a non-dealing message");
            };
            assert_eq!(dealing.id(), proposal);
        }

        let schemes = (0..committee.members().len())
            .map(|index| {
                bls12381::Scheme::signer(committee.clone(), clearing_private(index).unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for index in 0..quorum {
            let ballot = Ballot {
                deployment: protocol.deployment(),
                epoch: 0,
                proposal,
                context: expected.context.clone(),
                header: expected.header,
                roots: expected.roots,
                withdrawal_total: expected.withdrawal_total,
                vote: schemes[index].sign(&expected.header).unwrap(),
            };
            validator_channels[index].0.send(
                Recipients::One(operator_key.clone()),
                DaMessage::Vote(Box::new(ballot)).encode(),
                true,
            );
        }

        let certified = certify
            .await
            .unwrap()
            .expect("an exact quorum certifies without proof holders");
        assert_eq!(certified.context, expected.context);
        assert_eq!(certified.header, expected.header);
        assert_eq!(certified.roots, expected.roots);
        assert_eq!(certified.withdrawal_total, expected.withdrawal_total);
        assert!(verifier.verify_exact(&certified.header, &certified.certificate));
        assert_eq!(certified.certificate.signers.count(), quorum);
    });
}
