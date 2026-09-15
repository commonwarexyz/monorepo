use crate::bajillion::{
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    logs::Floors,
    payment::{SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorAck, VectorSendBody},
    replica::{Replica, ReplicaHead},
    transition::{
        CloseContext, CloseLimits, EpochContext, Header, OperatorKey, OperatorVariant, RootBundle,
        Terminal, prepare_close_with_strategy,
    },
    vector::{OutEntry, OutVector},
};
use bytes::Bytes;
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private as BlsPrivate, Scalar},
        ops::{compute_public, sign_message},
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{SigningKey, StrictVerifyingKey as VerifyingKey};
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_storage::Context;

pub const OPENING_BALANCE: u64 = 1_000_000;
const OPERATOR_SEED: u64 = 1;
const ACCOUNT_SEED_START: u64 = 10_000;
const WITHDRAWAL_DESTINATION: &[u8] = b"exit-destination";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Case {
    pub n: usize,
    pub a: usize,
    pub b: usize,
    pub k: usize,
    pub w: usize,
    pub h: usize,
}

impl Case {
    pub fn validate(self) {
        assert!(self.n > 0, "N must be positive");
        assert!(self.a <= self.n, "A must not exceed N");
        assert!(self.b > 0 && self.b <= self.n, "B must be in 1..=N");
        assert!(self.k > 0 && self.k <= self.b, "K must be in 1..=B");
        assert!(self.w <= self.n, "W must not exceed N");
        self.a.checked_mul(self.k).expect("A*K must fit usize");
    }

    pub fn label(self) -> String {
        format!(
            "N={} A={} B={} K={} W={} H={}",
            self.n, self.a, self.b, self.k, self.w, self.h
        )
    }
}

pub struct Keys {
    pub accounts: Vec<(VerifyingKey, SigningKey)>,
    pub operator: SigningKey,
    pub operator_bls: OperatorKey,
}

pub fn keys(n: usize) -> Keys {
    assert!(n > 0, "N must be positive");
    let mut accounts = (0..n)
        .map(|index| {
            let private = SigningKey::from_seed(ACCOUNT_SEED_START + index as u64);
            (private.public_key(), private)
        })
        .collect::<Vec<_>>();
    accounts.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    Keys {
        accounts,
        operator: SigningKey::from_seed(OPERATOR_SEED),
        operator_bls: compute_public::<OperatorVariant>(&BlsPrivate::new(Scalar::from(
            OPERATOR_SEED,
        ))),
    }
}

pub struct Built {
    pub context: CloseContext<VerifyingKey, Digest>,
    pub deposits: DepositBatch<VerifyingKey>,
    pub withdrawals: WithdrawalBatch<VerifyingKey, Digest>,
    pub encoded_dealing: Bytes,
    pub expected_head: ReplicaHead<Digest>,
    pub header: Header<Digest>,
    pub roots: RootBundle<Digest>,
    pub withdrawal_total: u64,
    pub rows: usize,
    pub mutations: usize,
    pub deletions: usize,
    pub row_count: u64,
    pub activity_append_operations: usize,
    pub activity_append_bytes: usize,
    pub payout_output_operations: usize,
    pub payout_output_bytes: usize,
    pub withdrawal_output_bytes: usize,
}

#[allow(clippy::too_many_arguments)]
pub async fn build_close<E, S>(
    replica: &Replica<E, Sha256, VerifyingKey, S>,
    case: Case,
    keys: &Keys,
    deployment: Digest,
    committee: Digest,
    epoch: u64,
    limits: CloseLimits,
    strategy: &S,
) -> Built
where
    E: Context + Spawner,
    S: Strategy,
{
    case.validate();
    assert_eq!(keys.accounts.len(), case.n, "key count must equal N");
    let admission_deadline = epoch
        .checked_mul(2)
        .and_then(|offset| 98_u64.checked_add(offset))
        .expect("benchmark admission deadline fits u64");
    let challenge_deadline = admission_deadline
        .checked_add(1)
        .expect("benchmark challenge deadline fits u64");
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::new(
        keys.accounts[..case.w]
            .iter()
            .map(|(_, signer)| {
                SignedWithdrawal::sign(
                    deployment,
                    replica.state().root().digest,
                    Bytes::from_static(WITHDRAWAL_DESTINATION),
                    WithdrawalAction::Close,
                    challenge_deadline,
                    signer,
                )
            })
            .collect(),
    )
    .expect("canonical benchmark withdrawals");
    let context = EpochContext::new::<Sha256>(
        deployment,
        epoch,
        keys.operator.public_key(),
        &deposits,
        &withdrawals,
        u64::try_from(case.n)
            .expect("benchmark account count fits u64")
            .checked_mul(OPENING_BALANCE)
            .expect("benchmark liability fits u64"),
        admission_deadline,
        challenge_deadline,
        limits,
        committee,
    )
    .expect("benchmark epoch context")
    .bind::<Sha256, _, _>(
        replica,
        &deposits,
        &withdrawals,
        Floors {
            activity: 0,
            payouts: 0,
        },
    )
    .expect("bound benchmark context");
    let terminals = terminals(case, keys, &context);
    let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        replica,
        &context,
        &deposits,
        &withdrawals,
        terminals,
        strategy,
    )
    .await
    .expect("prepare benchmark close");
    let close = prepared.close();
    let mutations = prepared.state().mutations().len();
    let deletions = prepared
        .state()
        .mutations()
        .iter()
        .filter(|(_, balance)| balance.is_none())
        .count();
    let withdrawal_output_bytes = close
        .withdrawal_outputs()
        .first()
        .map(|output| output.encode().len())
        .unwrap_or(0);
    let (_, activity_operations) = prepared.replica().logs().activity_operations();
    let (activity_append_operations, activity_append_bytes) = activity_operations
        .iter()
        .filter(|operation| {
            matches!(
                operation,
                crate::bajillion::logs::ActivityOperation::Append(_)
            )
        })
        .fold((0, 0), |(count, bytes), operation| {
            (count + 1, bytes + operation.encode().len())
        });
    let (_, payout_operations) = prepared.replica().logs().payout_operations();
    let (payout_output_operations, payout_output_bytes) = payout_operations
        .iter()
        .filter(|operation| {
            matches!(
                operation,
                crate::bajillion::logs::PayoutOperation::Append(_)
            )
        })
        .fold((0, 0), |(count, bytes), operation| {
            (count + 1, bytes + operation.encode().len())
        });
    let built = Built {
        context,
        deposits,
        withdrawals,
        encoded_dealing: prepared.encoded().clone(),
        expected_head: prepared.replica().head(),
        header: close.header,
        roots: close.roots,
        withdrawal_total: close.withdrawal_total,
        rows: close.rows.len(),
        mutations,
        deletions,
        row_count: close.roots.row_count,
        activity_append_operations,
        activity_append_bytes,
        payout_output_operations,
        payout_output_bytes,
        withdrawal_output_bytes,
    };
    drop(prepared);
    built
}

fn terminals(
    case: Case,
    keys: &Keys,
    context: &CloseContext<VerifyingKey, Digest>,
) -> Vec<Terminal<VerifyingKey, Digest>> {
    keys.accounts[..case.a]
        .iter()
        .enumerate()
        .map(|(index, account)| {
            let entries = (0..case.k)
                .map(|offset| OutEntry {
                    recipient: keys.accounts[(index + offset) % case.b].0.clone(),
                    cumulative: 1,
                    count: 1,
                })
                .collect::<Vec<_>>();
            terminal(account, context, &keys.operator, entries)
        })
        .collect()
}

fn terminal(
    account: &(VerifyingKey, SigningKey),
    context: &CloseContext<VerifyingKey, Digest>,
    operator: &SigningKey,
    mut entries: Vec<OutEntry<VerifyingKey>>,
) -> Terminal<VerifyingKey, Digest> {
    entries.sort_unstable_by(|a, b| a.recipient.cmp(&b.recipient));
    let debit = entries
        .iter()
        .try_fold(0_u64, |sum, entry| sum.checked_add(entry.cumulative))
        .expect("fixture debit fits u64");
    let vector = OutVector::new(context.payment().epoch(), account.0.clone(), entries)
        .expect("canonical benchmark vector");
    let body = VectorSendBody::new(
        context.payment(),
        account.0.clone(),
        0,
        debit,
        vector.root::<Sha256, Digest>().expect("vector root"),
    );
    let ack = VectorAck::sign_by_authorities(body, &account.1, operator);
    Terminal {
        authorization: SendAuthorization::from_raw_unchecked(
            ack.body().clone(),
            ack.payer_signature().clone(),
        ),
        vector,
        operator_signature: sign_message::<OperatorVariant>(
            &BlsPrivate::new(Scalar::from(OPERATOR_SEED)),
            VECTOR_ACK_AGGREGATE_NAMESPACE,
            ack.body().encode().as_ref(),
        ),
    }
}
