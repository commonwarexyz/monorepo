//! One test per (card, variant, mode), and the negative controls.
//!
//! Each test runs side A (the scenario's `drive`) and side B (the card's TSS
//! prefix) on identical setup and input bytes, prints the digests' sha256 and
//! whether they are equal on stdout, and, for a canonical positive test,
//! asserts the TSS prefix reached its handoff and the digests are equal. The
//! control run (`STATELENS_REACH_CONTROL=1`) and the negative controls assert
//! nothing: `statelens/scripts/differential.sh` reads the printed line and the
//! captured `[statelens-reach]` lines. With `DIFFERENTIAL_DIGESTS=<dir>`, a test
//! writes both digests to `<dir>/<test>.{a,b}.digest`, for a diff.

use crate::{
    cards::{self, Prefix, STAGE_DEADLINE, Twist},
    digest,
    record::Recorder,
    setup,
};
use commonware_consensus_fuzz_core::{Configuration, N4F0C4, N4F1C3, SimplexCertificateMock};
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::twins::stack::{
        DeferredMarshal, InlineMarshal, MarshalChoice, TwinsMarshal,
    },
    scenarios::{
        ScenarioKind,
        environment::{Mb, Node},
        harness::{App, FuzzScenarioStandardHarness},
        scenarios,
    },
};
use commonware_runtime::{Runner as _, deterministic};
use commonware_utils::FuzzRng;
use statelens_differential_shim::{
    deterministic::STATELENS_FRESH_RUN,
    simplex::statelens,
    target_states::{Knobs, Stages, control},
};
use std::time::Duration;

type P = SimplexCertificateMock;

/// The cards, each over one scenario kind.
#[derive(Clone, Copy, Debug)]
enum Card {
    Ts9001,
    Ts9002,
    Ts9003,
    Ts9004,
    Ts9005,
    Ts9006,
    Ts9007,
}

impl Card {
    fn id(self) -> &'static str {
        match self {
            Self::Ts9001 => cards::ts9001::CARD,
            Self::Ts9002 => cards::ts9002::CARD,
            Self::Ts9003 => cards::ts9003::CARD,
            Self::Ts9004 => cards::ts9004::CARD,
            Self::Ts9005 => cards::ts9005::CARD,
            Self::Ts9006 => cards::ts9006::CARD,
            Self::Ts9007 => cards::ts9007::CARD,
        }
    }

    fn stages(self) -> u32 {
        match self {
            Self::Ts9001 => cards::ts9001::STAGES,
            Self::Ts9002 => cards::ts9002::STAGES,
            Self::Ts9003 => cards::ts9003::STAGES,
            Self::Ts9004 => cards::ts9004::STAGES,
            Self::Ts9005 => cards::ts9005::STAGES,
            Self::Ts9006 => cards::ts9006::STAGES,
            Self::Ts9007 => cards::ts9007::STAGES,
        }
    }

    fn kind(self) -> ScenarioKind {
        match self {
            Self::Ts9001 => ScenarioKind::StandardCertifyMissingCandidateFetchesByRound,
            Self::Ts9002 => ScenarioKind::StandardCertifyFirstBlockFetchesGenesisParent,
            Self::Ts9003 | Self::Ts9004 => {
                ScenarioKind::StandardVerifyHeightLieParentFetchIsRoundBound
            }
            Self::Ts9005 => ScenarioKind::StandardCertifyBumpsNotarizedFetchForPendingVerify,
            Self::Ts9006 => ScenarioKind::StandardVerifyMissingCandidateWaitsWithoutFetching,
            Self::Ts9007 => ScenarioKind::StandardGetBlockByHeightAndLatest,
        }
    }

    async fn prefix<M: TwinsMarshal<P, App<P>>>(
        self,
        context: &deterministic::Context,
        stages: &mut Stages,
        recorder: &Recorder,
        harness: &mut FuzzScenarioStandardHarness<P, M>,
        mailbox: &Mb<P>,
        twist: Twist,
    ) -> Prefix<P> {
        match self {
            Self::Ts9001 => {
                cards::ts9001::prefix(context, stages, recorder, harness, mailbox, twist).await
            }
            Self::Ts9002 => {
                cards::ts9002::prefix(context, stages, recorder, harness, mailbox, twist).await
            }
            Self::Ts9003 => {
                cards::ts9003::prefix(context, stages, recorder, harness, mailbox, twist).await
            }
            Self::Ts9004 => {
                cards::ts9004::prefix(context, stages, recorder, harness, mailbox, twist).await
            }
            Self::Ts9005 => {
                cards::ts9005::prefix(context, stages, recorder, harness, mailbox, twist).await
            }
            Self::Ts9006 => {
                cards::ts9006::prefix(context, stages, recorder, harness, mailbox, twist).await
            }
            Self::Ts9007 => {
                cards::ts9007::prefix(context, stages, recorder, harness, mailbox, twist).await
            }
        }
    }
}

/// The runner tests' input bytes: the canonical input.
fn raw_bytes() -> Vec<u8> {
    vec![0u8; 64]
}

fn runner() -> deterministic::Runner {
    deterministic::Runner::new(deterministic::Config::new().with_rng(FuzzRng::new(raw_bytes())))
}

/// Side A: the scenario's own prefix, `finish`, the digest.
fn side_a<M: TwinsMarshal<P, App<P>>>(
    card: Card,
    byzantine: bool,
    marshal: MarshalChoice,
) -> String {
    runner().start(|mut context| async move {
        let recorder = Recorder::new("B=1");
        let (cluster, mut harness) =
            setup::cluster::<P, M>(&mut context, byzantine, marshal, recorder).await;
        let handoff = scenarios::drive::<P, M>(card.kind(), &mut harness).await;
        harness.finish(&handoff).await;
        digest::take(&context, &cluster, &harness, &handoff).await
    })
}

/// Side B: the TSS prefix through the helper, `finish` when it was reached and this is
/// not the control run, the digest, `done`.
fn side_b<M: TwinsMarshal<P, App<P>>>(
    card: Card,
    byzantine: bool,
    marshal: MarshalChoice,
    twist: Twist,
) -> (Option<String>, bool) {
    statelens::reset();
    let mut raw = raw_bytes();
    let knobs = Knobs::split(card.id(), &mut raw, 0);
    let mut stages = Stages::new(card.id(), card.stages());
    stages.budget(knobs, STAGE_DEADLINE * card.stages(), Duration::MAX);
    statelens::set_compromised(std::iter::empty::<usize>());
    // Where the materialized `Runner::new` calls the fresh-run hook.
    if let Some(hook) = STATELENS_FRESH_RUN.get() {
        hook();
    }
    let result = runner().start(|mut context| async move {
        let recorder = Recorder::new("B=1");
        let (cluster, mut harness) =
            setup::cluster::<P, M>(&mut context, byzantine, marshal, recorder.clone()).await;
        let mailbox = cluster.node(Node::B).mailbox.clone();
        let prefix = card
            .prefix::<M>(
                &context,
                &mut stages,
                &recorder,
                &mut harness,
                &mailbox,
                twist,
            )
            .await;
        let mut digest = None;
        if let Some(handoff) = &prefix.handoff
            && !control()
        {
            if prefix.reached {
                harness.finish(handoff).await;
            }
            digest = Some(digest::take(&context, &cluster, &harness, handoff).await);
        }
        stages.done();
        (digest, prefix.reached)
    });
    statelens::clear_compromised();
    result
}

/// Runs both sides and compares; `name` is the test's, for the digest files.
fn pair<M: TwinsMarshal<P, App<P>>>(
    name: &str,
    card: Card,
    config: Configuration,
    marshal: MarshalChoice,
    twist: Twist,
) {
    let byzantine = config.faults > 0;
    let a = side_a::<M>(card, byzantine, marshal);
    let (b, reached) = side_b::<M>(card, byzantine, marshal, twist);
    if let Ok(dir) = std::env::var("DIFFERENTIAL_DIGESTS") {
        let dir = std::path::Path::new(&dir);
        let _ = std::fs::write(dir.join(format!("{name}.a.digest")), &a);
        if let Some(b) = &b {
            let _ = std::fs::write(dir.join(format!("{name}.b.digest")), b);
        }
    }
    let equal = b.as_deref() == Some(a.as_str());
    println!(
        "digest-a={} digest-b={} digest-equal={equal} reached={reached}",
        digest::sha256(&a),
        b.as_deref().map_or_else(|| "-".to_string(), digest::sha256),
    );
    if twist == Twist::None && !control() {
        assert!(
            reached,
            "{}: the TSS prefix did not reach its handoff",
            card.id()
        );
        let b = b.expect("the TSS side took a digest");
        assert_eq!(a, b, "{}: the two sides' digests differ", card.id());
    }
}

macro_rules! pair_tests {
    ($card:ident: $($name:ident = $marshal:ident / $choice:ident / $config:ident;)*) => {
        $(
            #[test]
            fn $name() {
                pair::<$marshal>(
                    stringify!($name),
                    Card::$card,
                    $config,
                    MarshalChoice::$choice,
                    Twist::None,
                );
            }
        )*
    };
}

pair_tests!(Ts9001:
    ts9001_deferred_n4f0c4 = DeferredMarshal / Deferred / N4F0C4;
    ts9001_deferred_n4f1c3 = DeferredMarshal / Deferred / N4F1C3;
    ts9001_inline_n4f0c4 = InlineMarshal / Inline / N4F0C4;
    ts9001_inline_n4f1c3 = InlineMarshal / Inline / N4F1C3;
);
pair_tests!(Ts9002:
    ts9002_deferred_n4f0c4 = DeferredMarshal / Deferred / N4F0C4;
    ts9002_deferred_n4f1c3 = DeferredMarshal / Deferred / N4F1C3;
    ts9002_inline_n4f0c4 = InlineMarshal / Inline / N4F0C4;
    ts9002_inline_n4f1c3 = InlineMarshal / Inline / N4F1C3;
);
pair_tests!(Ts9003:
    ts9003_deferred_n4f0c4 = DeferredMarshal / Deferred / N4F0C4;
    ts9003_deferred_n4f1c3 = DeferredMarshal / Deferred / N4F1C3;
);
pair_tests!(Ts9004:
    ts9004_inline_n4f0c4 = InlineMarshal / Inline / N4F0C4;
    ts9004_inline_n4f1c3 = InlineMarshal / Inline / N4F1C3;
);
pair_tests!(Ts9005:
    ts9005_deferred_n4f0c4 = DeferredMarshal / Deferred / N4F0C4;
    ts9005_deferred_n4f1c3 = DeferredMarshal / Deferred / N4F1C3;
    ts9005_inline_n4f0c4 = InlineMarshal / Inline / N4F0C4;
    ts9005_inline_n4f1c3 = InlineMarshal / Inline / N4F1C3;
);
pair_tests!(Ts9006:
    ts9006_deferred_n4f0c4 = DeferredMarshal / Deferred / N4F0C4;
    ts9006_deferred_n4f1c3 = DeferredMarshal / Deferred / N4F1C3;
    ts9006_inline_n4f0c4 = InlineMarshal / Inline / N4F0C4;
    ts9006_inline_n4f1c3 = InlineMarshal / Inline / N4F1C3;
);
pair_tests!(Ts9007:
    ts9007_deferred_n4f0c4 = DeferredMarshal / Deferred / N4F0C4;
    ts9007_deferred_n4f1c3 = DeferredMarshal / Deferred / N4F1C3;
    ts9007_inline_n4f0c4 = InlineMarshal / Inline / N4F0C4;
    ts9007_inline_n4f1c3 = InlineMarshal / Inline / N4F1C3;
);

// Negative controls: a deliberately wrong TSS prefix. The script requires unequal
// digests or a verdict other than REACHED.

/// E1 (the armed delivery) dropped: certify never resolves, B lacks d.
#[test]
fn neg_ts9001_dropped_arm() {
    pair::<DeferredMarshal>(
        "neg_ts9001_dropped_arm",
        Card::Ts9001,
        N4F0C4,
        MarshalChoice::Deferred,
        Twist::Withhold(1),
    );
}

/// En's witness built before the handoff call: `handoff lost` with equal digests.
#[test]
fn neg_ts9002_stale_handoff_read() {
    pair::<DeferredMarshal>(
        "neg_ts9002_stale_handoff_read",
        Card::Ts9002,
        N4F0C4,
        MarshalChoice::Deferred,
        Twist::StaleHandoffRead,
    );
}

/// E3 (the arming) performed before E1 (verify) while recorded in card order: the
/// end state is the same, the stage order is not.
#[test]
fn neg_ts9005_swapped_arm_verify() {
    pair::<DeferredMarshal>(
        "neg_ts9005_swapped_arm_verify",
        Card::Ts9005,
        N4F0C4,
        MarshalChoice::Deferred,
        Twist::SwapArmAndVerify,
    );
}

/// The view-1 notarization also reported to C: C caches a certificate it has no block
/// for, which only the durable storage shows.
#[test]
fn neg_ts9001_notarization_to_c() {
    pair::<DeferredMarshal>(
        "neg_ts9001_notarization_to_c",
        Card::Ts9001,
        N4F0C4,
        MarshalChoice::Deferred,
        Twist::NotarizationToC,
    );
}

/// A garbage delivery armed on B that no fetch consumes: the fuzzing phase would
/// inherit it.
#[test]
fn neg_ts9002_armed_garbage() {
    pair::<DeferredMarshal>(
        "neg_ts9002_armed_garbage",
        Card::Ts9002,
        N4F0C4,
        MarshalChoice::Deferred,
        Twist::ArmGarbage,
    );
}

/// The first finalization reported to C instead of B: B never delivers height 1.
#[test]
fn neg_ts9007_finalization_to_c() {
    pair::<DeferredMarshal>(
        "neg_ts9007_finalization_to_c",
        Card::Ts9007,
        N4F0C4,
        MarshalChoice::Deferred,
        Twist::MisrouteFirstFinalization,
    );
}
