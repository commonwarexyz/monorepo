//! TS-9004 on marshal_scenario_standard_inline_cert_mock
//! Shape: B
//! Knobs: raw_bytes[0..0]: none
//! Stages: E1 exact verified; E2 construction wrapper_verify; E3 exact fetch, fetch_count,
//!     subscription (polled); E4 exact verified; E5 exact verify, fetch, targeted
//! Control: withholds E4
//! Injections: none (both verified writes are the source's own durability handshake)
//! Missing: none

// Source: `test_standard_verify_height_lie_parent_fetch_is_round_bound`
// (consensus/src/marshal/standard/mod.rs), the Inline tail, as
// `scenarios::StandardVerifyHeightLieParentFetchIsRoundBound@392b116687` drives it; the
// events are those of [`super::ts9003::height_lie`] under its Inline variant.

use super::{Prefix, Twist, ts9003};
use crate::record::Recorder;
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::twins::stack::TwinsMarshal,
    scenarios::{
        environment::Mb,
        harness::{App, FuzzScenarioStandardHarness},
    },
};
use commonware_runtime::deterministic;
use statelens_differential_shim::target_states::Stages;

pub const CARD: &str = "TS-9004";
pub const STAGES: u32 = 5;

pub async fn prefix<P: Simplex, M: TwinsMarshal<P, App<P>>>(
    context: &deterministic::Context,
    stages: &mut Stages,
    recorder: &Recorder,
    harness: &mut FuzzScenarioStandardHarness<P, M>,
    mailbox: &Mb<P>,
    twist: Twist,
) -> Prefix<P> {
    ts9003::height_lie(
        context,
        stages,
        recorder,
        harness,
        mailbox,
        twist,
        ts9003::Variant::Inline,
    )
    .await
}
