use super::{
    admission_fixtures::{SLICE_BITS, Validators, single_spans},
    fixtures::{
        active_close_fixture_with_assignment, profile_key, selected_active_profiles, strategy,
    },
};
use commonware_clearing::bajillion::{
    payment::EntryReceipt,
    posted,
    retained::{DealtBreakdown, DealtSlice, decode_dealt_slice_bounded},
    state::Prefix,
    transition::SliceBoundary,
    vector::{OutTipLookup, transpose_encode_size},
};
use commonware_codec::{Encode, EncodeSize, FixedSize};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_cryptography_curve25519::signing::StrictVerifyingKey as VerifyingKey;
use std::{collections::BTreeMap, ops::Range};

/// Prints the byte accounting for every selected profile.
pub(crate) fn benches() {
    let validators = Validators::new();
    for (_, profile) in selected_active_profiles() {
        let fixture = active_close_fixture_with_assignment(profile, validators.assignment());
        let close = fixture.prepared.close();
        let assignment = fixture.context.assignment();
        let slices = fixture
            .prepared
            .assemble_slices(&fixture.cache, &single_spans(), strategy())
            .expect("benchmark slices are valid");

        // The operator's dealing: every chunk once, plus a witness per single slice and per
        // distinct committee span.
        let mut spans = single_spans();
        spans.extend(validators.distinct_spans(assignment));
        let dealings = fixture
            .prepared
            .deal(&fixture.cache, &spans, strategy())
            .expect("benchmark dealing is valid");
        let slice_corpus = slices
            .iter()
            .map(|slice| slice.encoded_size())
            .sum::<usize>();
        let mut corpus = DealtBreakdown::default();
        let mut counts = Vec::with_capacity(slices.len());
        for slice in slices {
            // Per-slice shape for the closed-form check: predecessor leaves, rows, successor
            // leaves, transpose entries, senders, and recipient groups, plus the opening
            // positions the range proofs depend on and the full prefix at both boundaries
            // the varint boundary wire depends on.
            let (start, end) = (slice.coverage.start(), slice.coverage.end());
            let fields = |prefix: &Prefix| {
                (
                    prefix.debit,
                    prefix.credit,
                    prefix.payout,
                    prefix.deposit,
                    prefix.withdrawal,
                    prefix.withdrawal_count,
                    prefix.out_count,
                    prefix.in_count,
                )
            };
            let senders = slice
                .changes
                .rows
                .iter()
                .filter(|row| row.outgoing.is_some())
                .count();
            let mut groups = 0_usize;
            let mut previous = None;
            for entry in &slice.transpose {
                if previous != Some(&entry.recipient) {
                    groups += 1;
                    previous = Some(&entry.recipient);
                }
            }
            counts.push((
                start.predecessor,
                end.predecessor,
                start.change,
                end.change,
                start.successor,
                end.successor,
                start.prefix.in_count,
                end.prefix.in_count,
                senders,
                groups,
                fields(&start.prefix),
                fields(&end.prefix),
            ));
            let span = slice.span.clone();
            let stripped = DealtSlice::strip(slice, SLICE_BITS).breakdown();
            assert_eq!(stripped.total(), dealings.span_size(&span));
            corpus.add(&stripped);
        }
        println!("clearing slice counts: {} {counts:?}", profile_key(profile));
        let dealt_corpus = corpus.total();

        // Every validator's dealt share under the benchmark committee: the busiest is the
        // per-validator ingress, the sum is the operator's egress per close. Each distinct
        // span's wire is decoded once, as a holder decodes it, for its byte accounting.
        let mut breakdowns: BTreeMap<(u16, u16), DealtBreakdown> = BTreeMap::new();
        let mut breakdown = |span: &Range<u16>| {
            *breakdowns.entry((span.start, span.end)).or_insert_with(|| {
                let encoded = dealings.encode_span(span).encode();
                assert_eq!(encoded.len(), dealings.span_size(span));
                let breakdown = decode_dealt_slice_bounded::<VerifyingKey, Digest>(
                    encoded.as_ref(),
                    *fixture.context.limits(),
                    encoded.len(),
                )
                .expect("benchmark dealing decodes")
                .breakdown();
                assert_eq!(breakdown.total(), encoded.len());
                breakdown
            })
        };
        let mut busiest = DealtBreakdown::default();
        let mut dealt_egress = 0_usize;
        for spans in validators.spans(assignment) {
            let mut dealing = DealtBreakdown::default();
            for span in &spans {
                dealing.add(&breakdown(span));
            }
            if dealing.total() > busiest.total() {
                busiest = dealing;
            }
            dealt_egress += dealing.total();
        }
        let dealt_assignment = busiest.total();
        println!(
            "clearing dealt corpus breakdown: {} {corpus:?}",
            profile_key(profile)
        );
        println!(
            "clearing busiest dealing breakdown: {} {busiest:?}",
            profile_key(profile)
        );

        // A retained per-edge receipt: the dual-signed acknowledgment plus the entry opening a
        // sender DO hands the payer and recipient.
        let payer_position = 3_usize;
        let out_vector = &close.out_vectors[payer_position];
        let entry = out_vector.entries()[0].clone();
        let OutTipLookup::Present {
            cumulative,
            count,
            opening,
        } = out_vector
            .lookup::<Sha256, Digest>(&entry.recipient)
            .expect("fixture lookup is aligned")
        else {
            panic!("fixture entry is present");
        };
        let receipt = EntryReceipt {
            ack: fixture.acks[payer_position].clone(),
            recipient: entry.recipient.clone(),
            cumulative,
            count,
            opening,
        };
        receipt
            .verify::<Sha256>(fixture.context.payment())
            .expect("fixture receipt is valid");

        let terminal = fixture
            .prepared
            .terminal_proof()
            .expect("benchmark terminal proof is valid");
        let replica =
            posted::Replica::genesis(fixture.cache.leaves()).expect("genesis replica is canonical");
        println!(
            "clearing sizes: {} E={} rows={} unchanged_bytes={} rows_bytes={} out_vector_bytes={} transpose_bytes={} close_bytes={} slice_corpus_bytes={} dealt_slice_corpus_bytes={} dealt_assignment_bytes={} dealt_egress_bytes={} entry_receipt_bytes={} terminal_proof_bytes={} boundary_bytes={}",
            profile_key(profile),
            profile.edges(),
            close.rows.len(),
            close.unchanged.encode_size(),
            close.rows.encode_size(),
            close.out_vectors.encode_size(),
            transpose_encode_size(&fixture.transpose),
            posted::encoded_size(close, &replica).expect("posted size is computable"),
            slice_corpus,
            dealt_corpus,
            dealt_assignment,
            dealt_egress,
            receipt.encode_size(),
            terminal.encode_size(),
            SliceBoundary::SIZE,
        );
    }
}
