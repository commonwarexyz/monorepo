//! Fuzz driver over the `format` module's hostile-input decode surfaces.
//!
//! Compiled only for fuzzing (and tests, so it cannot rot). The fuzz target
//! feeds raw bytes; this module asserts the format layer's guarantees on
//! them: no panic, allocation bounded by the decode budget (enforced inside
//! decode itself), every outcome classified, and any accepted value
//! re-encoding byte-identically to the input it was decoded from (varints
//! have exactly one valid encoding, so decode and encode must be a bijection
//! on accepted bytes).

use super::format::{
    Checkpoint, CheckpointSeq, Decoded, Expect, Identity, Incarnation, LogId, LogOffset, PAGE,
    Record, Root, Salt, SegmentSeq, TxnSeq,
};

/// The fixed family identity fuzzed records must bind.
const INCARNATION: Incarnation = Incarnation(*b"fuzzfuzzfuzzfuzz");

/// Drives every decode surface with `data`, panicking only when a
/// format-layer guarantee is violated.
pub fn decode_surfaces(data: &[u8]) {
    // Two steering bytes pick the segment and sequence the reader expects,
    // so bindings beyond the trivial ones are reachable; the rest is the
    // hostile input.
    let (steer, buf) = match data {
        [a, b, rest @ ..] => ((*a, *b), rest),
        _ => return,
    };
    let ident = Identity {
        salt: Salt::new(&INCARNATION, 0),
        segment: SegmentSeq(steer.0 as u64),
    };
    let seq = steer.1 as u64;

    // Record decode under each expectation a reader can hold.
    for expect in [
        Expect::Frame(TxnSeq(seq)),
        Expect::Checkpoint(CheckpointSeq(seq)),
        Expect::Relocated {
            log: LogId(steer.0 as u64),
            at: LogOffset(steer.1 as u64),
        },
    ] {
        if let Decoded::Record(record, consumed) = Record::decode(buf, &ident, expect) {
            assert!(consumed <= buf.len(), "consumed past the input");
            let mut out = Vec::new();
            record.encode(&ident, &mut out);
            assert_eq!(out, &buf[..consumed], "record re-encode diverged");
        }
    }

    // Root decode for both slots: over a full page carrying the input, and
    // over the raw input (any non-page size must read as never-written).
    let mut page = vec![0u8; PAGE];
    let take = buf.len().min(PAGE);
    page[..take].copy_from_slice(&buf[..take]);
    for slot in [0, 1] {
        if let Ok(Some(root)) = Root::decode(&page, &INCARNATION, slot) {
            assert_eq!(root.encode(&INCARNATION), page, "root re-encode diverged");
        }
        if buf.len() != PAGE {
            assert!(matches!(Root::decode(buf, &INCARNATION, slot), Ok(None)));
        }
    }

    // Checkpoint decode from a located range covering the whole input.
    if let Ok(checkpoint) = Checkpoint::decode(buf, &ident, CheckpointSeq(seq)) {
        let mut out = Vec::new();
        checkpoint.encode(&ident, &mut out);
        assert_eq!(out, buf, "checkpoint re-encode diverged");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::format::{LogId, NetOp, ValidatedTxn},
        *,
    };

    /// The driver survives trivial and garbage inputs, and its re-encode
    /// assertions hold on genuine records reached through the steering
    /// bytes.
    #[test]
    fn decode_surfaces_smoke() {
        decode_surfaces(&[]);
        decode_surfaces(&[7]);
        decode_surfaces(&[7, 9]);
        decode_surfaces(&vec![0xA5; 2 + PAGE]);

        // A valid frame under the driver's identity: steering (7, 9) selects
        // segment 7 and expected sequence 9.
        let ident = Identity {
            salt: Salt::new(&INCARNATION, 0),
            segment: SegmentSeq(7),
        };
        let txn = ValidatedTxn::new(
            0,
            TxnSeq(9),
            vec![(
                LogId(1),
                NetOp::Create {
                    name: b"log".to_vec(),
                    run: b"payload".to_vec(),
                },
            )],
        )
        .unwrap();
        let mut data = vec![7, 9];
        txn.encode_frame(&ident, &mut data);
        decode_surfaces(&data);

        // A valid root page: sequence 8 lives in slot 0.
        let root = Root {
            seq: 8,
            epoch: 0,
            checkpoint: None,
            active_segment: SegmentSeq(1),
            replay_from: TxnSeq(0),
            replay_at: super::super::format::SEGMENT_RECORDS,
            next_log: LogId(0),
            next_txn: TxnSeq(0),
        };
        let mut root_page = vec![7, 9];
        root_page.extend_from_slice(&root.encode(&INCARNATION));
        decode_surfaces(&root_page);

        // A deterministic mini-fuzz standing in when the libFuzzer target
        // cannot run: random inputs, and bit-flipped valid encodings so the
        // deeper decode paths are reached.
        let mut rng = 0x9E3779B97F4A7C15u64;
        let mut next = move || {
            rng = rng.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = rng;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        };
        for _ in 0..2_000 {
            let len = (next() % 512) as usize;
            let data: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            decode_surfaces(&data);
        }
        let frame = {
            let mut data = vec![7, 9];
            let txn = ValidatedTxn::new(
                0,
                TxnSeq(9),
                vec![(
                    LogId(1),
                    NetOp::Create {
                        name: b"log".to_vec(),
                        run: b"payload".to_vec(),
                    },
                )],
            )
            .unwrap();
            txn.encode_frame(
                &Identity {
                    salt: Salt::new(&INCARNATION, 0),
                    segment: SegmentSeq(7),
                },
                &mut data,
            );
            data
        };
        for seed in [&frame, &root_page] {
            for _ in 0..2_000 {
                let mut data = seed.clone();
                for _ in 0..=next() % 3 {
                    let at = 2 + (next() as usize % (data.len() - 2));
                    data[at] ^= 1 << (next() % 8);
                }
                decode_surfaces(&data);
            }
        }
    }
}
