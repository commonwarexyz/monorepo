# Clearing

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

Modeled from `clearing/src/bajillion` on `main`: the module documentation,
including the obligations of each role (S1-S6, O1-O8, R1-R3, V1-V7, L1-L11),
`namespace.rs`, and the arithmetic in `settlement.rs`. The crate is ALPHA and
provides helper functions, not roles: storage, scheduling, persistence, and
recovery of every role belong to the deployment, and so does the ledger.

1. A summary is certified and posted that debits a sender beyond what it signed
   for the epoch, credits the wrong account, or pays a withdrawal its account
   did not request, because a post is final at once, a later challenge halts
   the ledger but reverts no post, and the ledger pays out against it.
2. A posted close credits a receiver less than a receipt it holds promises,
   because the operator preconfirmed that payment by countersigning it, the
   receiver's only remedy is a challenge, and a valid challenge halts the
   ledger for every account.
3. The ledger halts although the operator and the validators were honest,
   because after a halt the ledger posts nothing and takes no deposit or
   forced withdrawal, every account must exit through claims, and the
   deployment stops settling payments.
4. The same batch of payments settles twice, because both states carry the
   sender's own signature, validators accept both, the sender is debited twice
   for one intent, and no post is reverted.
5. A certified summary credits funds the ledger does not hold, because
   validators read ledger queues that the ledger's chain later reorders or a
   deposit was queued before the ledger took custody of it, the summary posts
   against other requests, and the accounts that withdraw last find the ledger
   short.
6. An honest validator's balances or payouts root differs from the posted
   roots, because it then refuses every later close or attests a summary that
   matches no honest validator's, it counts toward `f` until it reopens at a
   posted commit, replays the posted closes, or state syncs, and enough such
   validators leave the next close without a quorum.
7. No validator can open a posted matrix, serve a posted close, or prove a
   posted payout or balance, because a payout stays owed until its account
   withdraws it with a proof from a validator, so receivers cannot challenge,
   senders cannot resolve which of their states settled, other validators
   cannot apply the close, and accounts cannot withdraw or claim.
8. The ledger pays a payout or a claim twice, pays a balance the account does
   not have, or pays to a destination the caller chose, because the funds
   leave custody for good, and after a halt validators may serve proofs to
   anyone, so any holder of a balance proof could claim another account's
   balance.
9. The operator stops closing epochs or refuses an account's payments and soft
   withdrawals, because the account can leave only through a forced withdrawal
   that the next closes must process, or through claims once the deployment's
   own policy halts the ledger, and until then its funds are locked.
10. A posted payout is never paid although its account holds a valid proof,
    because the ledger kept only the latest payouts root, each post discards
    the root of every proof validators have served, and the operator can keep
    posting.
11. No close that validators accept exists for an epoch, because the
    countersigned rows or the deposits a close must process would take a
    balance below zero or past the largest amount, validators reject such a
    close instead of wrapping, the operator can only omit a countersigned row
    and be challenged or stop closing, and the ledger ends in a halt.
12. A forced withdrawal is queued that its account did not authenticate,
    because the account's balance is forced out of the system and the amount
    is revealed.
