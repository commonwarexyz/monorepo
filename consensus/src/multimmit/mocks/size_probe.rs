//! Written-size checks for artifacts and machine snapshots built from committee fixtures.

use super::Committee;
use crate::{
    Viewable as _,
    multimmit::{
        actors::testing::CoreDriver,
        config::{Profile, Role, Tuning},
        machine::{CoreState, Input, Snapshot, SnapshotCodecConfig},
        types::{Artifact, ChainId},
    },
    types::{Participant, View},
};
use commonware_codec::{EncodeSize, Read as _, Write};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use std::time::Duration;

fn check(label: &str, value: &(impl Write + EncodeSize)) {
    let before = value.encode_size();
    let mut buf = Vec::new();
    value.write(&mut buf);
    assert_eq!(
        buf.len(),
        before,
        "{label}: written bytes disagree with encode_size"
    );
    let mut again = Vec::new();
    value.write(&mut again);
    assert_eq!(
        (value.encode_size(), again.len()),
        (before, before),
        "{label}: size or bytes changed after the first write"
    );
}

#[test]
fn snapshot_writes_exactly_encode_size_with_forwarded_vqc() {
    for n in [6u32, 7, 11] {
        let committee = Committee::<MinPk>::builder(2000 + u64::from(n), n).build();
        let profile: Profile<Sha256Digest> = Profile::new::<MinPk>(
            committee.config.clone(),
            Role::Observer,
            Tuning {
                view_timeout: Duration::from_millis(500),
                production_interval: Duration::from_millis(100),
                ..Tuning::default()
            },
        )
        .unwrap();
        let mut core = CoreState::fresh(profile).unwrap();
        core.enqueue(Input::Start).unwrap();
        CoreDriver::new(&committee.verifier).settle_observing(
            &mut core,
            vec![
                Artifact::Vqc(committee.vqc(View::new(1))),
                Artifact::NoVote(committee.novote(Participant::new(0), View::new(2))),
            ],
        );
        let snapshot = core.machine().live_snapshot_for_test();
        let cut = core
            .machine()
            .checkpoint_cut()
            .expect("the driven core is quiescent");
        for artifact in cut.retained_artifacts() {
            if let Artifact::Vqc(vqc) = artifact.as_ref() {
                check(&format!("forwarded vqc view {:?}", vqc.view()), vqc);
                check(
                    &format!("forwarded leader view {:?}", vqc.view()),
                    vqc.leader(),
                );
                check(
                    &format!("forwarded tally view {:?}", vqc.view()),
                    vqc.tally(),
                );
            }
        }
        let mut written = Vec::new();
        snapshot.write(&mut written);
        assert_eq!(
            written.len(),
            snapshot.encode_size(),
            "snapshot size mismatch at n={n}"
        );

        // The written bytes decode back to an identical snapshot.
        let cfg = SnapshotCodecConfig::from_profile(core.machine().profile());
        let mut buf = bytes::Bytes::from(written.clone());
        let decoded =
            Snapshot::<MinPk, Sha256Digest>::read_cfg(&mut buf, &cfg).expect("snapshot decodes");
        assert_eq!(buf.len(), 0, "snapshot decode consumed every byte");
        let mut rewritten = Vec::new();
        decoded.write(&mut rewritten);
        assert_eq!(rewritten, written, "snapshot round-trips byte-identically");
    }
}

#[test]
fn every_artifact_writes_exactly_encode_size() {
    for n in [6u32, 7, 11, 16] {
        let committee = Committee::<MinPk>::builder(1000 + u64::from(n), n).build();
        let block = committee.leader_block(View::new(1));
        check("leader", &block);
        let vote = committee.vote(Participant::new(0), &block);
        check("vote", &vote);
        let vqc = committee.vqc(View::new(1));
        check("vqc", &vqc);
        let lqc = committee.lqc(View::new(1));
        check("lqc", &lqc);
        let nullification = committee.nullification(View::new(1));
        check("nullification", &nullification);
        let header = committee.transaction_header(ChainId::new(0), Sha256::hash(&[b"x"]));
        let signed = committee.signed_block(ChainId::new(0), header.body_digest());
        check("signed block", &signed);
        let da = committee.da_vote(Participant::new(1), header);
        check("da vote", &da);
        check(
            "novote",
            &committee.novote(Participant::new(2), View::new(1)),
        );
        check(
            "nullify",
            &committee.nullify(Participant::new(2), View::new(1)),
        );
    }
}
