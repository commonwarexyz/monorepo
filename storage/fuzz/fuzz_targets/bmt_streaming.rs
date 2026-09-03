#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_storage::bmt::{Builder, Error, StreamingBuilder};
use libfuzzer_sys::fuzz_target;

const MAX_LEAVES: usize = 128;

#[derive(Arbitrary, Debug)]
struct Input {
    leaves: Vec<u64>,
    subtree_log: u8,
    chunks: Vec<u8>,
}

fn dense_root(leaves: &[Digest]) -> Digest {
    let mut builder = Builder::<Sha256>::new(leaves.len());
    for leaf in leaves {
        builder.add(leaf);
    }
    builder.build(&Sequential).root()
}

fuzz_target!(|input: Input| {
    let leaves = input
        .leaves
        .into_iter()
        .take(MAX_LEAVES)
        .enumerate()
        .map(|(position, value)| {
            Sha256::hash(&[
                b"bmt-streaming",
                &(position as u32).to_be_bytes(),
                &value.to_be_bytes(),
            ])
        })
        .collect::<Vec<_>>();
    let expected = dense_root(&leaves);
    let subtree_size = 1usize << (input.subtree_log % 8);

    let mut streaming = StreamingBuilder::<Sha256>::new(leaves.len() as u32, subtree_size).unwrap();
    let mut start = 0;
    for chunk in input.chunks.into_iter().take(MAX_LEAVES * 2) {
        let remaining = leaves.len() - start;
        let take = usize::from(chunk) % (remaining + 1);
        streaming
            .extend(&leaves[start..start + take], &Sequential)
            .unwrap();
        start += take;
    }
    streaming.extend(&leaves[start..], &Sequential).unwrap();
    assert_eq!(streaming.finish(&Sequential).unwrap(), expected);

    // An overfeed is rejected before mutation, so the same builder can still
    // consume the declared stream and produce the canonical root.
    let mut over = StreamingBuilder::<Sha256>::new(leaves.len() as u32, subtree_size).unwrap();
    let extra = Sha256::hash(&[b"extra"]);
    let mut too_many = leaves.clone();
    too_many.push(extra);
    assert!(matches!(
        over.extend(&too_many, &Sequential),
        Err(Error::MismatchedLeafCount { .. })
    ));
    over.extend(&leaves, &Sequential).unwrap();
    assert_eq!(over.finish(&Sequential).unwrap(), expected);

    if !leaves.is_empty() {
        let mut under = StreamingBuilder::<Sha256>::new(leaves.len() as u32, subtree_size).unwrap();
        under
            .extend(&leaves[..leaves.len() - 1], &Sequential)
            .unwrap();
        assert!(matches!(
            under.finish(&Sequential),
            Err(Error::MismatchedLeafCount { .. })
        ));
    }
});
