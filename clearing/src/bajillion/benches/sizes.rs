use super::{
    admission_fixtures::{Validators, single_spans},
    fixtures::{
        active_close_fixture_with_assignment, profile_key, selected_active_profiles, strategy,
    },
};
use commonware_clearing::bajillion::{
    payment::EntryReceipt,
    posted,
    retained::DealtSlice,
    transition::SliceBoundary,
    vector::{OutTipLookup, transpose_encode_size},
};
use commonware_codec::{EncodeSize, FixedSize};
use commonware_cryptography::{Sha256, sha256::Digest};

/// Prints the byte accounting for every selected profile.
pub(crate) fn benches() {
    let validators = Validators::new();
    for (_, profile) in selected_active_profiles() {
        let fixture = active_close_fixture_with_assignment(profile, validators.assignment());
        let close = fixture.prepared.close();
        let slices = fixture
            .prepared
            .assemble_slices(&fixture.cache, &single_spans(), strategy())
            .expect("benchmark slices are valid");
        let slice_corpus = slices
            .iter()
            .map(|slice| slice.encoded_size())
            .sum::<usize>();
        let dealt_corpus = slices
            .into_iter()
            .map(|slice| DealtSlice::strip(slice).encode_size())
            .sum::<usize>();

        // Every validator's dealt share under the benchmark committee: the busiest is the
        // per-validator ingress, the sum is the operator's egress per close.
        let mut dealt_assignment = 0_usize;
        let mut dealt_egress = 0_usize;
        for spans in validators.spans(fixture.context.assignment()) {
            let bytes = fixture
                .prepared
                .assemble_slices(&fixture.cache, &spans, strategy())
                .expect("benchmark dealing is valid")
                .into_iter()
                .map(|slice| DealtSlice::strip(slice).encode_size())
                .sum::<usize>();
            dealt_assignment = dealt_assignment.max(bytes);
            dealt_egress += bytes;
        }

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
