use super::*;
use crate::chain::state::{machine_guard_key, machine_key};
use commonware_storage::qmdb::{any::value::VariableEncoding, current::ordered::ExclusionProof};

#[test]
fn certified_absence_omits_private_checkpoint_across_restart() {
    deterministic::Runner::default().start(|context| async move {
        let mut rng = test_rng();
        let SchemeFixture {
            participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, 4);
        let db = open(context.child("checkpoint_proofs"), "checkpoint-proofs").await;
        let requests = (0_u64..64)
            .map(|index| {
                req(Lookup::Deposit {
                    id: Sha256::hash(&[b"checkpoint-proof-contract", &index.to_le_bytes()]),
                })
            })
            .collect::<Vec<_>>();
        let (certificate, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            1,
            Vec::new(),
            &requests[0],
        )
        .await;
        assert_guard(&db, &deployment()).await;
        assert!(!check_absence(&db, &schemes[0], &certificate, &requests).await);

        let native = native();
        let owner = operator_signer(10);
        let funding = SettlementTx::NativeTransfer(NativeTransferRequest::sign(
            native.chain_id(),
            Sha256::hash(&[b"checkpoint-runtime-funding"]),
            owner.public_key(),
            10,
            wallets()[0].signer(),
        ));
        let registration = RegisterDeploymentRequest::sign(
            native.chain_id(),
            Sha256::hash(&[b"checkpoint-runtime-registration"]),
            operator_ack_key(10),
            ed25519::PrivateKey::from_seed(991_004).public_key(),
            1024,
            10,
            &owner,
        );
        let registered = registration.deployment_id();
        let transactions = vec![funding, SettlementTx::RegisterDeployment(registration)];
        let fork = execute(
            db.new_batches().await,
            Height::new(2),
            2,
            &Timing::DEFAULT,
            &native,
            &transactions,
        )
        .await
        .unwrap();
        for key in [machine_key(&registered), machine_guard_key(&registered)] {
            assert!(read(&db, &key).await.is_none());
            assert!(fork.get(&key).await.unwrap().is_some());
        }
        let successor = execute(
            fork.new_batch(),
            Height::new(3),
            3,
            &Timing::DEFAULT,
            &native,
            &[],
        )
        .await
        .unwrap();
        let expected_successor = (successor.root(), successor.ops_root());
        drop(successor);
        drop(fork);
        let (certificate, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            2,
            transactions,
            &requests[0],
        )
        .await;
        let requests = requests
            .into_iter()
            .flat_map(|request| {
                [
                    request.clone(),
                    ReadRequest::new(registered, request.lookup),
                ]
            })
            .collect::<Vec<_>>();
        for id in [deployment(), registered] {
            assert_guard(&db, &id).await;
        }
        assert!(!check_absence(&db, &schemes[0], &certificate, &requests).await);
        let (certificate, block) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            3,
            Vec::new(),
            &requests[0],
        )
        .await;
        assert_eq!((block.state_root, block.ops_root), expected_successor);
        for id in [deployment(), registered] {
            assert_guard(&db, &id).await;
        }
        let before = check_absence(&db, &schemes[0], &certificate, &requests).await;
        assert!(db.finalize().await.durable().await);
        drop(db);
        let db = open(context.child("reopened"), "checkpoint-proofs").await;
        assert_eq!(db.read().await.root(), block.state_root);
        for id in [deployment(), registered] {
            assert_guard(&db, &id).await;
        }
        let after = check_absence(&db, &schemes[0], &certificate, &requests).await;
        assert_eq!(before, after);
        assert!(
            !after,
            "public absence proofs must omit private checkpoints"
        );
    });
}

async fn assert_guard(db: &Database<deterministic::Context>, deployment: &Digest) {
    let machine = machine_key(deployment);
    let successor = machine_guard_key(deployment);
    assert_eq!(&machine.as_ref()[..32], &successor.as_ref()[..32]);
    assert_eq!(machine.as_ref()[32], 254);
    assert_eq!(successor.as_ref()[32], 255);
    assert!(machine < successor);
    assert_eq!(Record::MachineGuard.encode().len(), 1);
    assert_eq!(
        Record::decode(Record::MachineGuard.encode()).unwrap(),
        Record::MachineGuard
    );
    let guard = db.read().await;
    assert_eq!(
        guard.get(&successor).await.unwrap(),
        Some(Record::MachineGuard)
    );
    let record = guard.get(&machine).await.unwrap().unwrap();
    assert!(matches!(record, Record::Machine(_)));
    let proof = guard.key_value_proof(machine.clone()).await.unwrap();
    assert_eq!(proof.next_key, successor);
    assert!(proof.verify::<Sha256, VariableEncoding<Record>>(
        machine.clone(),
        record,
        &guard.root()
    ));
    assert!(guard.exclusion_proof(&machine).await.is_err());
    assert!(guard.exclusion_proof(&successor).await.is_err());
}

#[test]
fn public_lookup_encodings_exclude_private_checkpoint_suffixes() {
    let digest = Sha256::hash(&[b"lookup-contract-domain"]);
    let account = identities()[0].key.clone();
    let lookups = [
        Lookup::NativeBalance {
            chain_id: digest,
            account: account.clone(),
        },
        Lookup::Registry { chain_id: digest },
        Lookup::RegistryEntry {
            chain_id: digest,
            deployment: digest,
        },
        Lookup::NativeTransfer {
            chain_id: digest,
            from: account.clone(),
            id: digest,
        },
        Lookup::Status,
        Lookup::Anchor { epoch: u64::MAX },
        Lookup::Admitted { epoch: u64::MAX },
        Lookup::ClaimRoots { batch: digest },
        Lookup::Deposit { id: digest },
        Lookup::Registration,
        Lookup::Withdrawal {
            account: account.clone(),
        },
        Lookup::WithdrawalRelease {
            batch: digest,
            position: u32::MAX,
        },
        Lookup::HardFault {
            account: account.clone(),
        },
        Lookup::Refund {
            account: account.clone(),
            terminal: false,
        },
        Lookup::Refund {
            account,
            terminal: true,
        },
        Lookup::Fault,
    ];
    for lookup in lookups {
        let request = ReadRequest::new(digest, lookup);
        assert!(request.key().as_ref()[32] < 254);
        assert_eq!(ReadRequest::decode(request.encode()).unwrap(), request);
    }
}

async fn check_absence(
    db: &Database<deterministic::Context>,
    scheme: &Scheme,
    certificate: &CertifiedRead,
    requests: &[ReadRequest],
) -> bool {
    let mut contains_checkpoint = false;
    let mut rng = test_rng();
    let guard = db.read().await;
    for request in requests {
        let key = request.key();
        assert!(guard.get(&key).await.unwrap().is_none());
        let proof = guard.exclusion_proof(&key).await.unwrap();
        assert!(proof.verify::<Sha256>(&key, &guard.root()));
        if let ExclusionProof::KeyValue(_, update) = &proof {
            contains_checkpoint |= matches!(update.value, Record::Machine(_));
        }
        let response = CertifiedRead {
            finalization: certificate.finalization.clone(),
            block: certificate.block.clone(),
            proof: query::ReadProof::Absent { proof },
        };
        let encoded = ReadResponse::Certified(response.clone()).encode();
        assert!(encoded.len() <= rpc::MAX_BODY_SIZE);
        assert_eq!(
            ReadResponse::decode(encoded).unwrap(),
            ReadResponse::Certified(response.clone())
        );
        let verified = light::verify_read::<deterministic::Context, Scheme>(
            &mut rng, scheme, request, &response,
        )
        .unwrap();
        assert!(verified.record.is_none());
    }
    contains_checkpoint
}
