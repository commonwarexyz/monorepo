//! Written-size checks for artifacts built from scenario fixtures.

use super::{Committee, Scenario};
use crate::types::Participant;
use commonware_codec::{EncodeSize, Write};
use commonware_cryptography::bls12381::primitives::variant::MinPk;

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
fn every_artifact_writes_exactly_encode_size() {
    for n in [6u32, 7, 11, 16] {
        let mut scenario =
            Scenario::<MinPk>::new(Committee::builder(1000 + u64::from(n), n).build());
        let genesis = scenario.genesis();
        let raised = scenario.extend_all(genesis.tips(), 2);
        let first = scenario.advance(&genesis, &raised);
        check("leader", &scenario.leader_block(&first));
        check("header", scenario.block(&raised[0]).unwrap().header());
        check("signed header", scenario.block(&raised[0]).unwrap());

        // Every voter extends a different chain past the base, so the V-QC carries one deviation
        // and one resolution path per voter.
        let quorum = scenario.committee().codec().view_quorum();
        let mut contents = Vec::with_capacity(quorum);
        for signer in 0..quorum {
            let chain = signer % raised.len();
            let mut tips = raised.clone();
            tips[chain] = scenario.extend(&raised[chain], 1 + signer as u64 % 3);
            contents.push((
                Participant::from_usize(signer),
                scenario.vote(&first, true, &tips),
            ));
        }
        let (signer, content) = &contents[0];
        check("content", content);
        check(
            "update",
            &scenario.update(*signer, content, [&raised, &raised], 1),
        );
        let second = scenario.certify(&first, contents);
        check("vqc", second.vqc().unwrap().as_ref());
        check("record", second.record().unwrap().as_ref());
        check("lqc", &scenario.lqc(&second));
    }
}
