#![no_main]

use arbitrary::Arbitrary;
use commonware_clearing::bajillion::{
    Amounts, BalanceProof, Challenge, ChallengeError, Close, Epoch, Namespace, Opening,
    PayoutProof, Queue, Receipt, Row, State,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    Sha256, Signer as _, Verifier as _,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

type TestOpening = Opening<PublicKey, Digest, u64>;
type TestReceipt = Receipt<PublicKey, PublicKey, Digest, u64>;
type TestChallenge = Challenge<PublicKey, PublicKey, Digest, u64>;

/// The number of accounts that pay and are paid in a case.
const ACCOUNTS: usize = 4;

/// The epoch of a case's states and of the close that settles them.
const EPOCH: Epoch = 2;

/// The most changes a case applies to its proofs.
const MUTATIONS: usize = 8;

/// The deployment namespace every case signs in.
const NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_BAJILLION_FUZZ";

/// The signing keys of a case's accounts.
static USERS: LazyLock<Vec<PrivateKey>> =
    LazyLock::new(|| (0..).take(ACCOUNTS).map(PrivateKey::from_seed).collect());

/// The operator's signing key.
static OPERATOR: LazyLock<PrivateKey> = LazyLock::new(|| PrivateKey::from_seed(u64::MAX));

/// A change to the bytes of an encoded proof.
#[derive(Arbitrary, Debug)]
enum Mutation {
    Flip { position: u16, bit: u8 },
    Insert { position: u16, value: u8 },
    Delete { position: u16 },
    Replace { position: u16, value: u8 },
    Swap { first: u16, second: u16 },
}

impl Mutation {
    /// Changes the encoding of `value` and returns what the changed bytes decode to, if anything.
    fn apply<T: Encode + DecodeExt<()>>(&self, value: &T) -> Option<T> {
        let mut bytes = value.encode().to_vec();
        let at = |position: u16| usize::from(position).checked_rem(bytes.len());
        match *self {
            Self::Flip { position, bit } => {
                let position = at(position)?;
                bytes[position] ^= 1 << (bit % 8);
            }
            Self::Insert { position, value } => {
                let position = usize::from(position) % (bytes.len() + 1);
                bytes.insert(position, value);
            }
            Self::Delete { position } => {
                let position = at(position)?;
                bytes.remove(position);
            }
            Self::Replace { position, value } => {
                let position = at(position)?;
                bytes[position] = value;
            }
            Self::Swap { first, second } => {
                let (first, second) = (at(first)?, at(second)?);
                bytes.swap(first, second);
            }
        }
        T::decode(bytes).ok()
    }
}

/// Payments among the accounts in one epoch, the amounts the close of that epoch settles, and
/// changes to the proofs of one sender and receiver.
#[derive(Arbitrary, Debug)]
struct Payments {
    /// The amount each sender's countersigned map pays each receiver, zero for none.
    promised: [[u8; ACCOUNTS]; ACCOUNTS],
    /// The amount the close credits each receiver from each sender, zero for none.
    posted: [[u8; ACCOUNTS]; ACCOUNTS],
    /// The sender and receiver whose proofs are changed.
    pair: (u8, u8),
    /// A sender and receiver whose honest proofs are spliced into the pair's.
    other: (u8, u8),
    /// Changes to bytes, applied in turn to the pair's opening, receipt, and challenge.
    mutations: Vec<Mutation>,
}

/// A proof to verify, either arbitrary or derived from the honest proofs of a case.
#[allow(clippy::large_enum_variant)]
#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Opening {
        opening: TestOpening,
        root: Digest,
        sender: PublicKey,
        receiver: PublicKey,
    },
    Receipt {
        receipt: TestReceipt,
        operator: PublicKey,
    },
    Challenge {
        challenge: TestChallenge,
        operator: PublicKey,
        root: Digest,
    },
    PayoutProof {
        proof: PayoutProof<PublicKey, Digest, u64>,
        root: Digest,
    },
    BalanceProof {
        proof: BalanceProof<Digest, u64>,
        root: Digest,
        account: PublicKey,
    },
    Payments(Payments),
}

/// What the senders of a case promised and what its close posted. Whatever verifies must agree
/// with it.
struct Case {
    /// The signature namespaces of the deployment.
    namespace: Namespace,
    /// The operator's key.
    operator: PublicKey,
    /// The accounts, in the order the amounts below index them.
    accounts: Vec<PublicKey>,
    /// The countersigned state of each sender whose map pays anyone.
    states: Vec<Option<State<PublicKey, Digest>>>,
    /// The amount each sender promised each receiver, zero for none.
    promised: [[u64; ACCOUNTS]; ACCOUNTS],
    /// The amount the close credits each receiver from each sender, zero for none.
    posted: [[u64; ACCOUNTS]; ACCOUNTS],
    /// The root of each sender's row in the posted matrix, if it has one.
    rows: Vec<Option<Digest>>,
    /// The root of the posted matrix.
    root: Digest,
}

impl Case {
    /// Returns the index of `account`. A verified proof must name one of the case's accounts.
    fn index(&self, account: &PublicKey) -> usize {
        self.accounts
            .iter()
            .position(|candidate| candidate == account)
            .expect("a verified proof must name an account of the case")
    }

    /// Checks that `opening` verifies for a sender and receiver only as what the close credits
    /// that pair.
    fn check_opening(&self, opening: &TestOpening) {
        for (sender, account) in self.accounts.iter().enumerate() {
            if let Ok(row) = opening.verify_row::<Sha256>(&self.root, account) {
                assert_eq!(row, self.rows[sender]);
            }
            for (receiver, paid) in self.accounts.iter().enumerate() {
                if let Ok(credited) = opening.verify::<Sha256>(&self.root, account, paid) {
                    assert_eq!(credited, self.posted[sender][receiver]);
                }
            }
        }
    }

    /// Returns whether `receipt` verifies, in which case it must carry both signatures over the
    /// state its sender signed and state what that sender promised.
    fn check_receipt(&self, receipt: &TestReceipt) -> bool {
        if !receipt.verify::<Sha256>(&self.namespace, &self.operator) {
            return false;
        }
        let state = &receipt.state;
        let encoded = state.encode();
        let signed = state
            .account
            .verify(&self.namespace.state, &encoded, &receipt.signature);
        let acknowledged = self.operator.verify(
            &self.namespace.acknowledgement,
            &encoded,
            &receipt.acknowledgement,
        );
        assert!(signed && acknowledged);
        let sender = self.index(&state.account);
        let receiver = self.index(&receipt.receiver);
        assert_eq!(self.states[sender].as_ref(), Some(state));
        assert_eq!(receipt.amount, self.promised[sender][receiver]);
        assert_ne!(receipt.amount, 0);
        true
    }

    /// Checks that `challenge` verifies against the posted matrix only with a receipt its sender
    /// issued for more than the close credits.
    fn check_challenge(&self, challenge: &TestChallenge) {
        let verified =
            challenge.verify::<Sha256>(&self.namespace, &self.operator, EPOCH, &self.root);
        if verified.is_err() {
            return;
        }
        let receipt = &challenge.receipt;
        assert!(self.check_receipt(receipt));
        let sender = self.index(&receipt.state.account);
        let receiver = self.index(&receipt.receiver);
        assert!(self.posted[sender][receiver] < receipt.amount);
    }
}

/// Builds the honest proofs of a case and checks them, then checks that no change to the proofs of
/// one sender and receiver makes them verify as anything the case does not hold.
fn payments(input: Payments) {
    let namespace = Namespace::new(NAMESPACE);
    let accounts: Vec<_> = USERS.iter().map(PrivateKey::public_key).collect();
    let amounts = |row: &[u8; ACCOUNTS]| {
        let entries = accounts.iter().cloned().zip(row.map(u64::from));
        Amounts::new(entries.filter(|(_, amount)| *amount != 0))
            .expect("distinct accounts with nonzero amounts must collect")
    };

    // Each sender whose map pays anyone signs its state, the operator countersigns it, and the
    // sender issues a receipt to every receiver.
    let previous = Amounts::<PublicKey, u64>::empty().root::<Sha256>();
    let mut states = Vec::with_capacity(ACCOUNTS);
    let mut receipts = Vec::new();
    for (user, row) in USERS.iter().zip(&input.promised) {
        let payments = amounts(row);
        if payments.is_empty() {
            states.push(None);
            continue;
        }
        let state = State {
            epoch: EPOCH,
            account: user.public_key(),
            payments: payments.root::<Sha256>(),
            previous,
        };
        let signature = user.sign(&namespace.state, &state.encode());
        let acknowledgement = state.acknowledge(&*OPERATOR, &namespace);
        let receivers = payments.iter().map(|(receiver, _)| receiver.clone());
        let issued = TestReceipt::issue::<Sha256>(
            &state,
            &signature,
            &acknowledgement,
            &payments,
            receivers,
        )
        .expect("a state's map must open each of its receivers");
        receipts.extend(issued);
        states.push(Some(state));
    }

    // The close settles the posted rows, whatever the senders signed. Assembly checks no row's
    // signature, so every row carries the same one.
    let signature = OPERATOR.sign(&namespace.state, &[]);
    let rows = accounts
        .iter()
        .zip(&input.posted)
        .filter_map(|(account, row)| {
            let payments = amounts(row);
            (!payments.is_empty()).then(|| Row {
                account: account.clone(),
                payments,
                signature: signature.clone(),
            })
        });
    let queue = Queue {
        epoch: EPOCH,
        deposits: Vec::new(),
        required_deposits: 0,
        forced_withdrawals: Vec::new(),
        required_forced_withdrawals: 0,
    };
    let (close, _) = Close::<PublicKey, PublicKey, u64>::assemble::<Sha256, _>(
        &*OPERATOR,
        &namespace,
        &queue,
        rows,
        [],
        0,
        0,
        &Sequential,
    )
    .expect("nonempty rows of distinct senders must assemble");
    let matrix = close.matrix::<Sha256>(&Sequential);
    let case = Case {
        namespace,
        operator: OPERATOR.public_key(),
        states,
        promised: input.promised.map(|row| row.map(u64::from)),
        posted: input.posted.map(|row| row.map(u64::from)),
        rows: accounts
            .iter()
            .map(|account| matrix.payments_root(account))
            .collect(),
        root: matrix.root(),
        accounts,
    };

    // The opening of every sender and receiver verifies as what the close credits them.
    for (sender, account) in case.accounts.iter().enumerate() {
        for (receiver, paid) in case.accounts.iter().enumerate() {
            let opening = matrix.open(account, paid);
            assert_eq!(
                opening.verify_row::<Sha256>(&case.root, account).ok(),
                Some(case.rows[sender])
            );
            assert_eq!(
                opening.verify::<Sha256>(&case.root, account, paid).ok(),
                Some(case.posted[sender][receiver])
            );
            case.check_opening(&opening);
        }
    }

    // A receipt the sender issued verifies. With the opening of its sender and receiver, it is a
    // challenge exactly when the close credits less than it promises.
    let pick = |(sender, receiver): (u8, u8)| {
        let sender = usize::from(sender) % ACCOUNTS;
        let receiver = usize::from(receiver) % ACCOUNTS;
        let (account, paid) = (&case.accounts[sender], &case.accounts[receiver]);
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.state.account == *account && receipt.receiver == *paid);
        (
            sender,
            receiver,
            matrix.open(account, paid),
            receipt.cloned(),
        )
    };
    let (sender, receiver, mut opening, mut receipt) = pick(input.pair);
    if let Some(receipt) = &receipt {
        assert!(case.check_receipt(receipt));
        let challenge = Challenge {
            receipt: receipt.clone(),
            opening: opening.clone(),
        };
        let verify =
            |epoch| challenge.verify::<Sha256>(&case.namespace, &case.operator, epoch, &case.root);
        let contradicted = case.posted[sender][receiver] < case.promised[sender][receiver];
        assert_eq!(verify(EPOCH).is_ok(), contradicted);
        assert!(matches!(
            verify(EPOCH + 1),
            Err(ChallengeError::WrongEpoch { .. })
        ));
    }

    // Proofs spliced from the parts of two honest ones verify only as the case holds.
    let (_, _, other, issued) = pick(input.other);
    for spliced in [
        TestOpening {
            row: opening.row.clone(),
            entry: other.entry.clone(),
        },
        TestOpening {
            row: other.row.clone(),
            entry: opening.entry.clone(),
        },
        TestOpening {
            row: opening.row.clone(),
            entry: None,
        },
    ] {
        case.check_opening(&spliced);
        if let Some(receipt) = &receipt {
            case.check_challenge(&Challenge {
                receipt: receipt.clone(),
                opening: spliced,
            });
        }
    }
    if let (Some(receipt), Some(issued)) = (&receipt, issued) {
        case.check_receipt(&TestReceipt {
            amount: issued.amount,
            ..receipt.clone()
        });
        case.check_receipt(&TestReceipt {
            state: issued.state,
            signature: issued.signature,
            acknowledgement: issued.acknowledgement,
            ..receipt.clone()
        });
    }

    // Each change to bytes keeps what still decodes, and whatever then verifies must agree with
    // the case.
    for mutation in input.mutations.iter().take(MUTATIONS) {
        if let Some(changed) = mutation.apply(&opening) {
            opening = changed;
        }
        case.check_opening(&opening);
        let Some(receipt) = &mut receipt else {
            continue;
        };
        if let Some(changed) = mutation.apply(receipt) {
            *receipt = changed;
        }
        case.check_receipt(receipt);
        let challenge = Challenge {
            receipt: receipt.clone(),
            opening: opening.clone(),
        };
        case.check_challenge(&challenge);
        if let Some(changed) = mutation.apply(&challenge) {
            case.check_challenge(&changed);
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    let namespace = Namespace::new(NAMESPACE);
    match input {
        // Arbitrary proofs must be judged without panicking, whatever they are checked against.
        FuzzInput::Opening {
            opening,
            root,
            sender,
            receiver,
        } => {
            let _ = opening.verify_row::<Sha256>(&root, &sender);
            let _ = opening.verify::<Sha256>(&root, &sender, &receiver);
        }
        FuzzInput::Receipt { receipt, operator } => {
            let _ = receipt.verify::<Sha256>(&namespace, &operator);
        }
        FuzzInput::Challenge {
            challenge,
            operator,
            root,
        } => {
            let epoch = challenge.receipt.state.epoch;
            let _ = challenge.verify::<Sha256>(&namespace, &operator, epoch, &root);
        }
        FuzzInput::PayoutProof { proof, root } => {
            let _ = proof.verify::<Sha256>(&root);
        }
        FuzzInput::BalanceProof {
            proof,
            root,
            account,
        } => {
            let _ = proof.verify::<Sha256, _>(&root, &account);
        }
        FuzzInput::Payments(input) => payments(input),
    }
});
