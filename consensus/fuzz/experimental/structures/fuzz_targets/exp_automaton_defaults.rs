#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::{
    Application, Automaton, CertifiableAutomaton, Handoff,
    marshal::{
        ancestry::{self, Ancestry},
        mocks::block::{Block, ready},
    },
    simplex::{scheme::ed25519::Scheme, types::Context},
    types::{Height, Round},
};
use commonware_cryptography::{Digested, Digestible as _, Sha256, ed25519::PublicKey, sha256};
use commonware_runtime::{Runner, deterministic};
use commonware_utils::{Entropy, FuzzRng, channel::oneshot};
use libfuzzer_sys::fuzz_target;

type Ctx = Context<sha256::Digest, PublicKey>;
type TestBlock = Block<sha256::Digest, Ctx>;

const MAX_ANCESTORS: u64 = 4;

#[derive(Debug)]
struct FuzzInput {
    context: Ctx,
    round: Round,
    payload: sha256::Digest,
    ancestors: u64,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            context: u.arbitrary()?,
            round: u.arbitrary()?,
            payload: u.arbitrary()?,
            ancestors: u.int_in_range(0..=MAX_ANCESTORS)?,
            entropy: u.arbitrary()?,
        })
    }
}

/// An automaton that implements only what consensus requires, so it prepares and certifies as
/// the trait does by default.
#[derive(Clone)]
struct RequiredAutomaton;

impl Automaton for RequiredAutomaton {
    type Context = Ctx;
    type Digest = sha256::Digest;

    async fn propose(&mut self, _: Ctx) -> oneshot::Receiver<sha256::Digest> {
        oneshot::channel().1
    }

    async fn verify(&mut self, _: Ctx, _: sha256::Digest) -> oneshot::Receiver<bool> {
        oneshot::channel().1
    }
}

impl CertifiableAutomaton for RequiredAutomaton {}

/// An application that implements only what the marshal requires, so it prepares as the trait
/// does by default.
#[derive(Clone)]
struct RequiredApplication;

impl Application<deterministic::Context> for RequiredApplication {
    type SigningScheme = Scheme;
    type Context = Ctx;
    type Block = TestBlock;
    type Input = ();

    async fn propose(
        &mut self,
        _: (deterministic::Context, Ctx),
        _: impl Ancestry<TestBlock>,
        _: (),
    ) -> Option<Digested<TestBlock>> {
        None
    }

    async fn verify(
        &mut self,
        _: (deterministic::Context, Ctx),
        _: impl Ancestry<TestBlock>,
    ) -> bool {
        true
    }
}

/// Returns `ancestors` contiguous blocks built on the context's parent, newest first.
fn chain(context: &Ctx, ancestors: u64) -> Vec<Digested<TestBlock>> {
    let mut parent = context.parent.1;
    let mut blocks: Vec<_> = (1..=ancestors)
        .map(|height| {
            let height = Height::new(height);
            let block = TestBlock::new::<Sha256>(context.clone(), parent, height, height.get());
            parent = block.digest();
            ready(block)
        })
        .collect();
    blocks.reverse();
    blocks
}

fn fuzz(input: FuzzInput) {
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(input.entropy));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|runtime| async move {
        // An automaton that does not prepare waits for the parent to certify.
        let prepared = RequiredAutomaton.prepare(input.context.clone()).await;
        assert_eq!(prepared.await.ok(), Some(Handoff::Wait));

        // An automaton that does not certify accepts every payload of every round.
        let certified = RequiredAutomaton.certify(input.round, input.payload).await;
        assert_eq!(certified.await.ok(), Some(true));

        // An application that does not prepare waits, whatever ancestry it is offered.
        let ancestry = ancestry::from_iter(chain(&input.context, input.ancestors));
        let prepared = RequiredApplication
            .prepare((runtime, input.context), ancestry, ())
            .await;
        assert!(prepared.is_wait());
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
