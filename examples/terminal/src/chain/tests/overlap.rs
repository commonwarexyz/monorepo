//! Successor payments across a held predecessor close on the distributed chain.

use super::*;
use std::sync::mpsc::TryRecvError;

/// Genesis timing for the overlap walkthrough. Epoch 0's admission window must
/// span the held close, every successor payment made meanwhile, and the
/// distributed certification and admission that follow the release.
const TIMING: Timing = Timing {
    admission_offset: 120,
    challenge_duration: 2,
};

/// Custody once both epochs settle: the genesis balances, Alice's deposit
/// pulled into epoch 0, and Bob's deposit pulled into epoch 1.
const CUSTODY: u64 = 419;

/// Lets the close worker's OS thread compute between runtime steps.
async fn tick(context: &deterministic::Context) {
    std::thread::sleep(Duration::from_millis(2));
    context.sleep(Duration::from_millis(10)).await;
}

/// Unwraps a payment concluded with verified receipts.
fn paid(outcome: PaymentOutcome) -> anyhow::Result<operator_rpc::AcceptedBatchResponse> {
    match outcome {
        PaymentOutcome::Accepted(payment) => Ok(*payment),
        PaymentOutcome::CommittedUnheld { epoch, .. } => {
            anyhow::bail!("epoch {epoch} payment committed without receipts")
        }
    }
}

/// The inbox index settlement assigned to one certified deposit.
async fn index(
    context: &deterministic::Context,
    chain: &mut Client,
    deposit: &DepositEvent,
) -> anyhow::Result<u64> {
    let effect = chain
        .deposit(context, deposit.id)
        .await?
        .context("the deposit has no custody record")?;
    anyhow::ensure!(
        effect.event == *deposit,
        "the custody record holds another deposit"
    );
    Ok(effect.index)
}

/// Pays across a predecessor close held at `stage`, then settles both epochs
/// through the validators.
///
/// While epoch 0's close is held, a cold wallet and a wallet whose cached
/// context is epoch 1 are accepted in epoch 1. A wallet whose cached context is
/// the cut epoch 0 is accepted in epoch 1 too, signed again against the
/// endpoint the operator reports. After the release, epoch 0 certifies and
/// admits, and epoch 1, whose validators check that payment against epoch 0's
/// account rows, certifies, admits, and finalizes behind epoch 0. The admitted
/// roots, the finalized state, the liabilities the closes bind, and every
/// balance must agree.
pub(super) async fn run(
    context: deterministic::Context,
    genesis: Genesis,
    operator: std::net::SocketAddr,
    queries: Vec<std::net::SocketAddr>,
    sqlite: Arc<Mutex<Operator>>,
    stage: Stage,
) -> anyhow::Result<()> {
    let mut alice = Agent::new(0)?;
    let mut bob = Agent::new(1)?;
    let mut carol = Agent::new(2)?;
    let mut dave = Agent::new(3)?;
    let mut alice_chain = Client::new(
        &genesis,
        deployment(),
        queries.clone(),
        context.child("alice"),
    )?;
    let mut bob_chain = Client::new(
        &genesis,
        deployment(),
        queries.clone(),
        context.child("bob"),
    )?;
    let mut carol_chain = Client::new(
        &genesis,
        deployment(),
        queries.clone(),
        context.child("carol"),
    )?;
    let mut dave_chain = Client::new(&genesis, deployment(), queries, context.child("dave"))?;

    // Alice's deposit precedes any registration, so epoch 0 pulls it. Her
    // balance poll caches epoch 0's context.
    let pulled = alice.deposit(&context, &mut alice_chain, 10).await?;
    anyhow::ensure!(
        index(&context, &mut alice_chain, &pulled).await? == 0,
        "the first deposit took another inbox index"
    );
    observed_balance(&context, &mut alice, &mut alice_chain, operator, 110).await?;

    // Alice's first payment registers epoch 0.
    let first = paid(
        alice
            .pay(&context, &mut alice_chain, operator, &[(1, 2)])
            .await?,
    )?;
    anyhow::ensure!(
        first.epoch == 0,
        "the first payment landed in a foreign epoch"
    );

    // Bob's deposit executes while epoch 0 is registered, so it waits in the
    // inbox past epoch 0's pull.
    let late = bob.deposit(&context, &mut bob_chain, 9).await?;
    anyhow::ensure!(
        index(&context, &mut bob_chain, &late).await? == 1,
        "the deposit during a registered epoch took another inbox index"
    );

    // The operator cuts epoch 0, and its close worker holds at the stage.
    let (started, release) = sqlite.lock().pause_close_at(stage);
    let close = alice.start_close(&context, operator).await?;
    anyhow::ensure!(close.epoch == 0, "the operator cut a foreign epoch");
    loop {
        match started.try_recv() {
            Ok(()) => break,
            Err(TryRecvError::Empty) => tick(&context).await,
            Err(TryRecvError::Disconnected) => {
                anyhow::bail!("the close worker never reached the held stage")
            }
        }
    }

    // Bob's balance poll shows his deposit credited to epoch 1 and caches
    // epoch 1's context.
    observed_balance(&context, &mut bob, &mut bob_chain, operator, 111).await?;

    // Carol, a cold wallet, pays in epoch 1. Her first receipt registers
    // epoch 1 behind the unadmitted epoch 0 and binds its certified anchor.
    let cold = paid(
        carol
            .pay(&context, &mut carol_chain, operator, &[(3, 3)])
            .await?,
    )?;
    let queued = carol_chain
        .registration_at(&context, 1)
        .await?
        .context("epoch 1 is not registered")?;
    anyhow::ensure!(
        cold.epoch == 1
            && cold.acceptance.ack.body().anchor() == &queued.anchor
            && queued.deadlines.is_none(),
        "the cold payment did not bind the queued epoch-1 registration"
    );

    // Bob signs from his cached epoch-1 context.
    let warm = paid(
        bob.pay(&context, &mut bob_chain, operator, &[(2, 4)])
            .await?,
    )?;
    anyhow::ensure!(
        warm.epoch == 1,
        "the warm payment landed in a foreign epoch"
    );

    // Alice's cached context is the cut epoch 0. The operator reports her
    // frozen epoch-0 endpoint, which her first receipt confirms, so the payment
    // is signed again under epoch 1, bound to that endpoint's root, and
    // receipted while epoch 0 is held.
    let resigned = paid(
        alice
            .pay(&context, &mut alice_chain, operator, &[(1, 5)])
            .await?,
    )?;
    let body = resigned.acceptance.ack.body();
    anyhow::ensure!(
        resigned.epoch == 1
            && body.seq() == 1
            && body.cumulative_debit() == 5
            && body.anchor() == &queued.anchor
            && resigned.acceptance.ack.predecessor() == first.acceptance.ack.body().send_root(),
        "the stale payment was not signed again under epoch 1 against Alice's epoch-0 terminal"
    );
    anyhow::ensure!(
        alice_chain.admitted(&context, 0).await?.is_none(),
        "epoch 0 was admitted while its close was held"
    );

    // The released close certifies through the validators and admits, which
    // makes epoch 1 the frontier.
    release
        .send(())
        .context("the held close worker exited early")?;
    let predecessor = loop {
        if let Some(admitted) = alice_chain.admitted(&context, 0).await? {
            break admitted;
        }
        tick(&context).await;
    };
    let promoted = alice_chain
        .registration_at(&context, 1)
        .await?
        .context("epoch 1 lost its registration")?;
    anyhow::ensure!(
        promoted.anchor == queued.anchor && promoted.deadlines.is_some(),
        "epoch 0's admission did not promote epoch 1"
    );
    anyhow::ensure!(
        alice_chain.admitted(&context, 1).await?.is_none(),
        "epoch 1 admitted ahead of epoch 0"
    );

    // Epoch 1 certifies, admits, and finalizes behind epoch 0.
    let finished = walkthrough_close(&context, &mut alice, operator).await?;
    anyhow::ensure!(finished.epoch == 1, "the close finished a foreign epoch");
    let status = alice_chain.status(&context).await?;
    anyhow::ensure!(
        status.last_finalized == Some(1)
            && status.custody == CUSTODY
            && status.claimable == 0
            && !status.hard_faulted,
        "the end state did not settle: {status:?}"
    );
    anyhow::ensure!(
        alice_chain.registration(&context).await?.is_none(),
        "a registration outlived finality"
    );

    // The certified closes bind the chain's admitted roots, chain epoch 1 to
    // epoch 0's admitted head, and carry the liabilities the operator
    // projected: the genesis balances, then Alice's pulled deposit on top.
    let (zero, one) = {
        let operator = sqlite.lock();
        (
            operator
                .retained_result(0)?
                .context("epoch 0 has no certified close")?,
            operator
                .retained_result(1)?
                .context("epoch 1 has no certified close")?,
        )
    };
    let successor = alice_chain
        .admitted(&context, 1)
        .await?
        .context("the finalized epoch lost its admitted record")?;
    anyhow::ensure!(
        predecessor.roots == zero.roots && successor.roots == one.roots && successor.finalized,
        "the admitted roots differ from the certified closes"
    );
    anyhow::ensure!(
        one.context.predecessor_root() == &zero.roots.successor
            && one.context.predecessor_logs() == &zero.roots.logs(),
        "epoch 1 is not bound to epoch 0's admitted head"
    );
    anyhow::ensure!(
        zero.context.predecessor_liability() == 400
            && one.context.predecessor_liability() == 400 + pulled.amount,
        "the certified liabilities differ from the operator's projection"
    );

    // All three native roots agree: the finalized state root and payout head
    // are epoch 1's certified roots, and the operator's replica serves the
    // same state.
    anyhow::ensure!(
        status.state_root == one.roots.successor,
        "the finalized state root differs from epoch 1's close"
    );
    let payouts = alice_chain.payout_checkpoint(&context).await?;
    anyhow::ensure!(
        payouts.payouts == one.roots.withdrawal_outputs && payouts.finalized == Some(1),
        "the finalized payout head differs from epoch 1's close"
    );

    // Every verified balance reflects each payment once and both deposits.
    for (agent, chain, expected) in [
        (&mut alice, &mut alice_chain, 103),
        (&mut bob, &mut bob_chain, 112),
        (&mut carol, &mut carol_chain, 101),
        (&mut dave, &mut dave_chain, 103),
    ] {
        let balance = agent.balance(&context, chain, operator).await?;
        anyhow::ensure!(
            balance == expected,
            "verified balance {balance} differs from {expected}"
        );
    }
    let head = operator_rpc::payment_head(
        &context,
        operator,
        operator_rpc::PaymentHeadRequest {
            account: dave.account(),
        },
    )
    .await?;
    anyhow::ensure!(
        head.floor_epoch == 2 && head.root == status.state_root,
        "the operator replica serves another finalized state"
    );
    Ok(())
}

/// Runs the overlap walkthrough with epoch 0's close held at `stage`.
fn hold(stage: Stage) {
    let mut engine = Walkthrough::timed(1, TIMING);
    engine.hold = Some(stage);
    PlanBuilder::new(engine)
        .seed(0)
        .timeout(Duration::from_secs(300))
        .exit_condition(WalkthroughDone {
            deployments: vec![deployment()],
        })
        .property(ClientSucceeded)
        .property(Monotonic)
        .run()
        .unwrap();
}

#[test]
fn held_preparation_keeps_successor_payments_live() {
    hold(Stage::Prepare);
}

#[test]
fn held_certification_keeps_successor_payments_live() {
    hold(Stage::Certify);
}

#[test]
fn held_admission_keeps_successor_payments_live() {
    hold(Stage::Admit);
}
