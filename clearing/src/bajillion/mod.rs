//! Clear payments between accounts through an operator, and settle each epoch's net effect at once.
//!
//! Bajillion runs between users, an operator, a committee of validators, and a ledger that holds
//! deposited funds. Users pay each other through the operator, and the operator preconfirms each
//! payment by countersigning it. To end an epoch, the operator closes it. Validators check the
//! close against the balances of the last posted close and certify a [Summary] of its effects. The
//! ledger posts the summary once a certificate verifies over it, and the post is final at once. A
//! challenge can later halt the ledger, but it reverts no post.
//!
//! # One epoch
//!
//! Users act as senders and receivers, so each epoch involves five roles and follows the same
//! steps. Deposits and forced withdrawals wait in the ledger's queues. A sender pays receivers
//! through the operator and gives each a receipt. The operator closes the epoch over the oldest
//! queued requests, validators check the close and certify its summary, and the ledger posts it.
//! Each role then acts on the post.
//!
//! ```text
//!   sender           operator          receiver         validators          ledger
//!      |                 |                 |                 |                 |
//!      | states, sign    |                 |                 |                 |
//!      |---- Request --->|                 |                 |                 |
//!      |                 | verify, admit,  |                 |                 |
//!      |                 | fits?, persist  |                 |                 |
//!      |<----- Ack ------|                 |                 |                 |
//!      | verify, persist |                 |                 |                 |
//!      | issue receipts  |                 |                 |                 |
//!      |------------- Receipt ------------>|                 |                 |
//!      |                 |                 | verify,         |                 |
//!      |                 |                 | keep largest    |                 |
//!      |                 |                 |                 |                 |
//!      |                 |<----------------------------------|<-- queue(e) ----|
//!      |                 | assemble        |                 |                 |
//!      |                 |------------ Close(e) ------------>|                 |
//!      |                 |                 |                 | check, settle,  |
//!      |                 |                 |                 | certify         |
//!      |                 |                 |                 |-- Summary(e) -->|
//!      |                 |                 |                 |                 | verify, post,
//!      |                 |                 |                 |                 | owe payouts
//!      |                 |                 |                 |                 x final
//!      |<----------------|<----------------|<----------------|<-- posted(e) ---|
//!      |                 | apply flows     |                 | apply batches   |
//!      |<----------------------------------|<-- Opening -----|                 |
//!      | resolve         |                 | compare         |                 |
//!      |                 |                 |                 |                 |
//!      |                 |                 |------- Challenge, if short ------>|
//!      |                 |                 |                 |                 | verify, halt
//! ```
//!
//! Each arrow carries a protocol message, except queue(e) and posted(e), the final ledger state the
//! roles read. Each label in a lane is a step that role takes. Validators serve openings of the
//! posted matrix. A receiver whose receipt promises more than the post credits challenges the post,
//! and the ledger halts. Every account then claims what the last post left it.
//!
//! # Trust model
//!
//! The operator may be malicious. It cannot debit a sender beyond what the sender signed for the
//! epoch or credit the wrong account. Nor can it pay out a withdrawal its account did not request,
//! since a soft withdrawal carries the account's signature and the ledger queues a forced
//! withdrawal only on a request the account authenticated.
//!
//! It can refuse payments and soft withdrawals, and users can still withdraw through the ledger
//! with forced withdrawals the next closes must process. If it omits preconfirmed payments from a
//! close, a receiver's challenge halts the ledger. If it stops closing epochs, accounts exit
//! through claims once the deployment's policy halts the ledger.
//!
//! At most `f` validators may be Byzantine. The deployment chooses the certificate scheme and its
//! fault model, and the scheme's quorum must exceed `f` while honest validators alone must still
//! reach it. Every certificate then includes an honest validator that checked the close and keeps
//! the data needed to open its matrix and to apply it.
//!
//! # Helpers, not roles
//!
//! The crate prescribes what independent parties must compute identically. These are the wire
//! formats and signature [Namespace]s, the commitments (payment maps, the payment [Matrix], the
//! summary chain, the balances root, and the payouts root), the rules for checking and settling a
//! close, the challenge, post, payout, and claim checks, and the ledger's queue rule. Each is a
//! function on a protocol type that reads no storage.
//!
//! The exceptions are the validators' two [QMDB](commonware_storage::qmdb) databases. The root of
//! the [Balances] database commits to every write ever made to it, not only to the balances it
//! holds, so applying a posted close to it is prescribed as well. The root of the [PayoutLog]
//! commits to every payout and commit in the order appended, so each posted close appends exactly
//! the batch [Payout::stage] builds. Everything else belongs to the deployment. That covers what
//! each role stores and where, and how it caches, batches, schedules, persists, and recovers.
//!
//! Each deployment also chooses the unsigned integer type of its amounts ([Amount]). This crate
//! implements it for `u64` and `u128`, and a deployment that settles EVM tokens can implement it
//! for its own 256-bit integer type.
//!
//! ```text
//!   role        keeps                 calls
//!   ---------------------------------------------------------------------------------------------
//!   sender      any store             Request::states, States::sign,
//!                                     State::verify_acknowledgement, Receipt::issue,
//!                                     Opening::verify_row, Withdrawal::sign
//!   operator    any store             Request::verify, Verified::admit, State::acknowledge,
//!                                     Withdrawal::verify, Close::assemble, Flow::settle
//!   receiver    any store             Receipt::verify, Opening::verify, Challenge::verify
//!   validators  Balances, PayoutLog,  Close::check, Checked::settle, Proposal::apply,
//!               any store             Proposal::payouts, Matrix::open, Queue::prefix
//!   ledger      any store             Summary::verify, Challenge::verify, PayoutProof::verify,
//!                                     BalanceProof::verify
//!   ---------------------------------------------------------------------------------------------
//!   prescribed  wire formats, namespaces, commitments, close rules, the balances and payout log
//!               steps
//! ```
//!
//! Each role's section below names its helpers and states its obligations. An obligation is a
//! precondition the crate cannot check, followed by what happens when a deployment breaks it. A
//! sender's or receiver's obligations protect only that account, as long as the operator keeps its
//! own. An operator that breaks one can get its close rejected or halt the ledger, and a validator
//! that breaks one counts against the `f` faulty validators the trust model tolerates. The ledger's
//! obligations protect the funds themselves.
//!
//! Every role reads the ledger's queues, posts, and halts only from ledger state that cannot be
//! reverted, and "posted" always means final on the ledger's chain. If the chain reorders a queue
//! after validators read it, a certified summary posts against other requests, and the balances
//! root credits funds the ledger does not hold.
//!
//! For each queue, a summary holds a running hash over every request the queue has processed from
//! genesis up to and including the summary's close. Anyone holding the ledger's requests can
//! recompute the hashes and detect a summary posted against other requests. The hashes cannot
//! prevent that post, because the ledger checks each count against its queue but never recomputes
//! a hash.
//!
//! # Senders
//!
//! For each epoch, a sender keeps a payment map ([Amounts]) from each receiver to the cumulative
//! amount the operator has countersigned for it. To pay a batch of receivers, it adds the batch to
//! its latest countersigned map of the epoch and signs a [State] committing to the new map and to
//! the map the previous close settled for it.
//!
//! [Request::states] derives the states, and [States::sign] signs them into a [Request]. A signer
//! outside the process signs each state's encoding in [Namespace::state], and [States::request]
//! builds the request from those signatures.
//!
//! The operator countersigns the state it admits, and the sender checks that acknowledgement with
//! [State::verify_acknowledgement]. [Receipt::issue] then gives each receiver a [Receipt] holding
//! the state, both signatures, and an opening of the receiver's cumulative amount. A receipt
//! preconfirms the payment, because the close of its epoch must credit at least that amount or its
//! receiver can halt the ledger.
//!
//! A pipelined request also signs a state for the next epoch that pays only the batch, on top of
//! the map without it. A payment refused because its epoch just closed then settles in the next
//! epoch without a new request. Each state commits to the root it builds on, so the sender's row in
//! the close of the request's epoch decides which of the two can settle.
//!
//! ```text
//!              close(e-1)               close(e)                 close(e+1)
//!                  row                     row                       row
//!
//!   state(e)    previous <---------- root(M + batch)                                pays in e
//!                                          or
//!   state(e+1)                           root(M) <-------------- root(batch)        pays in e+1
//!
//!   M   latest countersigned map of e         <--   builds on
//! ```
//!
//! If close(e) settles M + batch, state(e+1) builds on a root no close settled and never settles.
//! If close(e) settles M, the operator can admit state(e+1) in epoch e+1. The sender learns which
//! happened from the row root [Opening::verify_row] proves under each post's matrix root.
//!
//! - **S1.** Derive a request's states from the latest countersigned map of its epoch and from
//!   `previous`. Until the close of the epoch before posts, `previous` is the root of the latest
//!   countersigned map of that epoch. Once it posts, it is the posted row root. Either is the empty
//!   map's root when there is none. Sign no request while another may still be countersigned, and
//!   none for an epoch before one with a countersigned map. Otherwise [Verified::admit] refuses the
//!   state, and the sender's requests fail until a post shows which map settled.
//!
//! - **S2.** Record a map as countersigned only once [State::verify_acknowledgement] accepts the
//!   operator's acknowledgement of its state. Otherwise the sender's record diverges as in S1, and
//!   its receivers reject the receipts.
//!
//! - **S3.** Persist each request with its [States] before sending it. On an acknowledgement,
//!   persist the state, both signatures, and the map in one write that clears the request, before
//!   releasing any receipt. Otherwise a crash leaves the sender unable to issue receipts the close
//!   still settles, or to extend its map until a post resolves the epoch.
//!
//! - **S4.** Treat a refusal as final only for a request delivered once, with no copy in flight.
//!   Otherwise an earlier copy may have been admitted, and the record diverges as in S1.
//!
//! - **S5.** Resolve a pending request against each post from its epoch on, in epoch order, before
//!   dropping it or building on a posted row root. The request settled in epoch `e` if it has a
//!   state of `e` whose root equals the row root the post of `e` proves, and it is dropped once
//!   none of its states is for a later epoch. Otherwise the sender drops a request a close settled,
//!   or builds on the wrong root.
//!
//! # The operator
//!
//! The operator admits payments and soft withdrawals, closes each epoch, and tracks what each
//! account can spend. [Request::verify] reads no storage and checks the sender's signature over the
//! state a request asks for in the current epoch. [Verified::admit] compares that state with the
//! operator's record of the sender and returns an [Admission]. The operator then checks that a new
//! state fits the sender's balance and the validators' limits, persists it, and countersigns it
//! with [State::acknowledge].
//!
//! ```text
//!                                      +---------------- Retry --------------->+
//!                                      |                                       v
//!   Request --> verify --Verified--> admit --New--> fits? --> persist --> acknowledge --> Ack
//!                  :                   ^              ^          |
//!            reads nothing             | latest map,  | balance, | state, map,
//!                                      | row in e-1   | deducted | signature
//!                                      |              |          |
//!                                      |              |          v
//!                                +-----+--------------+----------+-----------+
//!                                |        operator store, any layout         |
//!                                +-------------------------------------------+
//! ```
//!
//! A retry repeats the latest countersigned state, so the operator countersigns it again and
//! nothing is paid twice. A new state, its map, and the sender's signature form the sender's [Row]
//! in the close. The store's layout is the deployment's, because the helpers take the records they
//! compare against as arguments.
//!
//! The ledger fixes which queued requests the close of epoch e must process only when the post of
//! e-1 is final. The operator then cuts epoch e. It fixes the epoch's rows, assembles its close,
//! and opens e+1 at once. Validators certify close(e) while the operator admits e+1.
//!
//! ```text
//!   admit      |============ e ===========|=========== e+1 ==========|=========== e+2 ==========>
//!
//!   close(e-1)  -- certify, post ---------x
//!   close(e)                              |- assemble, certify, post x
//!   close(e+1)                                                       |- assemble, ... ---------->
//!
//!                                         ^                          ^
//!                                  post(e-1) final             post(e) final
//!                                  cut e, open e+1           cut e+1, open e+2
//! ```
//!
//! [Close::assemble] takes the rows and the honored soft [Withdrawal]s in any order, with how many
//! queued [Deposit]s and [ForcedWithdrawal]s to process. It recomputes every root, signs the close,
//! and returns each touched account's [Flow]. [Flow::settle] applies a flow with the rule
//! validators use, so an operator that applies the flows of each posted close holds the balances
//! validators hold.
//!
//! An account asks for a soft withdrawal by signing a [Withdrawal] with [Withdrawal::sign]. The
//! operator honors one only if [Withdrawal::verify] accepts it, because [Close::assemble] checks no
//! signature and validators reject a close that holds a forged one.
//!
//! Until it applies close(e), the operator admits e+1 against a floor. It deducts from each account
//! everything close(e) may take from it. These are the payments the account made in e and the soft
//! and forced withdrawals it asked for. Credits only add and a payout never exceeds its request, so
//! close(e) leaves each balance at or above its floor.
//!
//! ```text
//!                0                         floor                            B, after close(e-1)
//!   balance      |============|==============|------------------------------|
//!                  paid in e+1    spendable       close(e) may take this
//! ```
//!
//! One process can admit every account. A deployment whose traffic exceeds one machine routes
//! accounts to shards, each admitting its own accounts with the operator's key. The shards' rows
//! and soft withdrawals assemble into one close, and each flow goes back to the shard serving its
//! account.
//!
//! ```text
//!                   +--> shard A  records -- rows, withdrawals -+
//!                   |              ^                            |
//!   requests ------>+--> shard B  records -- rows, withdrawals -+--> Close::assemble --> Close(e)
//!   by account      |              ^                            |           |
//!                   +--> shard C  records -- rows, withdrawals -+           |
//!                                  ^                                        |
//!                                  '--- flows, by account, after post(e) ---'
//! ```
//!
//! The operator's obligations follow. Breaking O1 or O6 costs the operator or its senders, and
//! breaking any other halts the ledger or gets a close rejected.
//!
//! - **O1.** Verify each request with [Request::verify] before reading anything stored about its
//!   sender. Otherwise forged requests cost the operator storage reads.
//!
//! - **O2.** Admit each sender's states in one place at a time, each extending the latest
//!   countersigned one, and pass [Verified::admit] that latest state and its map. Countersign no
//!   state of an epoch for a sender once its row of that epoch is fixed, or after any of its states
//!   of the next epoch. Otherwise a countersigned state is missing from its close, and its
//!   receiver's challenge halts the ledger.
//!
//! - **O3.** Countersign a new state only if its batch fits the sender's spendable balance, its
//!   balance as of the last close applied less what unapplied closes may take and what it paid in
//!   the epoch. Fix which forced withdrawals close(e) processes before countersigning anything of
//!   e+1, and lift a deduction only by applying that account's flow. Otherwise a close overdrafts,
//!   and no acceptable close exists for its countersigned rows. Omitting a row lets its receiver's
//!   challenge halt the ledger, and posting no close leaves the halt to the deployment's policy.
//!
//! - **O4.** Pass [Verified::admit] the root of the sender's row in the close of the epoch before
//!   as `previous`, or the empty map's root if it has no row. Otherwise the operator countersigns
//!   states validators refuse, with the outcome of O3.
//!
//! - **O5.** Keep each epoch's rows, receivers per row, and soft withdrawals within the validators'
//!   [Limits], and honor only soft withdrawals [Withdrawal::verify] accepts. [Close::assemble]
//!   checks neither. Otherwise validators cannot decode the close or reject it. Rows are
//!   countersigned, so too many rows or receivers end as in O3, while a soft withdrawal that is
//!   forged or over the limit only needs assembling again without it.
//!
//! - **O6.** When a request arrives after its own epoch closed, verify it with [Request::verify]
//!   for the next epoch, and admit its pipelined state if [Verified::admit] and the checks of O3
//!   and O5 accept it. Otherwise a payment refused because its epoch just closed needs a new
//!   request.
//!
//! - **O7.** Persist each [Admission::New] state with its map and the sender's signature before
//!   releasing its acknowledgement, each close with its counts before releasing it, and the
//!   balances with the epoch of the last flows applied. Otherwise a crash loses a preconfirmed
//!   payment, a released close, or which flows were applied.
//!
//! - **O8.** Release one close per epoch, and assemble it again, with the same rows, only after
//!   validators reject it. Apply the flows of the close that posts exactly once each, in epoch
//!   order ([Flow::epoch]). Otherwise the operator's balances part from the validators', and it
//!   admits payments a later close cannot settle.
//!
//! # Receivers
//!
//! A receiver relies on receipts while their epoch is open and audits each post. [Receipt::verify]
//! checks both signatures and the receipt's entry under the state's payments root. After a post,
//! the receiver gets an opening of the posted matrix from a validator for every sender it holds
//! receipts from. [Opening::verify] returns what the post credits, and if that is less than a
//! receipt, the receiver submits a [Challenge] holding the receipt and the opening.
//!
//! ```text
//!          post(1)       post(2)       post(3)                    halt
//!   ---------+-------------+-------------+----------------------x---------> time
//!                          ^                                    |
//!                          '------- challenge against post(2) --'
//! ```
//!
//! A challenge halts the ledger even after later closes posted, and those closes stay final. It
//! stops the operator but does not restore the omitted payment, because claims pay balances as of
//! the last post.
//!
//! - **R1.** Rely on a receipt only if it names this account as receiver, [Receipt::verify] accepts
//!   it under the deployment's namespace and operator key, the close of its epoch has not posted,
//!   and the ledger has not halted. Verify it before comparing it with the receipts held. Otherwise
//!   the receiver relies on a payment it cannot enforce, and a refusal that depends on what it
//!   holds reveals that to whoever sent a forged receipt.
//!
//! - **R2.** Keep, per epoch and sender, the receipt with the largest amount, persisted before
//!   relying on it. Otherwise, after an omission, it may hold no receipt above the posted amount
//!   and cannot challenge.
//!
//! - **R3.** Before discarding a receipt, compare it with what the post of its epoch credits from
//!   its sender, and submit a challenge if the post credits less. Accept no receipt of an epoch
//!   after that comparison. Otherwise an omitted or reduced payment goes unchallenged, and the
//!   receiver loses it.
//!
//! # Validators
//!
//! A validator checks each close as the successor of the last post, settles it on its balances, and
//! certifies the summary. [Close::check] takes the close, the [Checkpoint] of the last post, and
//! the ledger's [Queue], and reads no storage. It checks the epochs and counts, the operator's
//! signature before any user's, each sender's signature over a state built on its row in the parent
//! matrix, and each soft withdrawal. [Checked::settle] reads the touched balances at the parent's
//! root and stages the close's writes in a [Proposal].
//!
//! Each balance gains its incoming payments and deposits, loses its outgoing payments, and must end
//! between zero and the largest amount. An account withdrawing is then paid the lesser of what it
//! asked for and its balance. The summary chains to the one before it and commits to the payments,
//! the new balances, and the payout log. For each queue it holds a [Processed] record of how many
//! requests the close processes and the queue's running hash after them. The post carries the
//! proposal's summary and its certificate.
//!
//! Every payout joins one [PayoutLog] and keeps its index there for good. [Checked::settle] stages
//! the close's batch with [Payout::stage], and the summary records the log's root and size after
//! the batch. With p the parent's payouts size and s the close's, the close's payouts take the
//! indices [p, s - 1) in account order and its commit takes s - 1 ([Proposal::payouts]). A
//! validator can find an account's payout of a close by binary search over [p, s - 1) and prove it
//! with the log's proof of that one operation ([PayoutProof]).
//!
//! ```text
//!   Summary(e)
//!   +-------+--------+--------+----------+-------------+--------------+--------------------+
//!   | epoch | parent | matrix | balances |   payouts   |   deposits   | forced withdrawals |
//!   |       |        |        |          | root | size | count | hash |  count   |  hash   |
//!   +-------+--------+--------+----------+------+------+-------+------+----------+---------+
//!               |        |         |        |       |             |                   |
//!               v        |         |        |       |             '---------+---------'
//!        H(Summary(e-1)) |         |        |       |                       v
//!                        |         |        |       |      hash in Summary(e-1), extended by
//!                        |         |        |       |      H(hash || request) for each request
//!                        |         |        |       |      the close processes, in queue order
//!                        |         |        '-------+--> root and size of PayoutLog after the
//!                        |         |                     close's payouts and commit
//!                        |         '--> root of Balances, keyed by account
//!                        v
//!                   matrix root
//!                  /           \
//!     H(alice || a_root)     H(bob || b_root)      one leaf per sender
//!             |
//!             v
//!           a_root
//!          /      \
//!   H(bob || 5)  H(carol || 2)                     alice's payment map, one leaf per receiver
//! ```
//!
//! Once the close posts, [Proposal::apply] applies both batches and returns both databases with the
//! close's [Checkpoint]. Before touching either database, it refuses a proposal whose summary did
//! not post, balances not at the parent's balances root, or a payout log not at the parent's
//! payouts root. It commits the log's batch before it applies the balance writes. It does not make
//! the balance writes durable, and committing and pruning the balances leave their root unchanged.
//!
//! Applied balance writes can survive a crash before the balances commit, so after a crash the
//! balances may hold either close. Because the log is durable first, it is then at or past the
//! close the balances hold. A restart rewinds it by reopening it at that close's payouts size (V2).
//!
//! Because each root commits to every write, an empty batch changes it and the same balances
//! reached through other batches give another root. Validators therefore apply one batch to each
//! database per posted close, in epoch order, each the batch [Checked::settle] staged at its
//! parent's roots.
//!
//! ```text
//!                       apply after              apply after            apply after
//!                     post(e-1) final           post(e) final         post(e+1) final
//!                            v                        v                      v
//!   PayoutLog L(e-2) -- batch(e-1) --> L(e-1) --- batch(e) ---> L(e) -- batch(e+1) --> L(e+1)
//!                            |                        |                      |
//!                       once durable             once durable           once durable
//!                            v                        v                      v
//!   Balances  R(e-2) -- batch(e-1) --> R(e-1) --- batch(e) ---> R(e) -- batch(e+1) --> R(e+1)
//!                                                                ^
//!                                                                |
//!                                               settle of close(e+1) reads R(e) and L(e)
//!                                                 and stages both of its batches
//! ```
//!
//! Settling close(e+1) reads R(e) and L(e), so it waits for close(e) to apply. Checking close(e+1)
//! needs only the checkpoint of close(e).
//!
//! The validators' obligations follow. V4 and V6 put funds at risk if every honest validator in a
//! certificate breaks them.
//!
//! - **V1.** Attest only the summary of a [Proposal] that [Checked::settle] returned. Otherwise the
//!   validator certifies a close it did not check.
//!
//! - **V2.** Pass [Close::check] the checkpoint of the last post, the one [Proposal::apply]
//!   returned. After a restart, take the persisted summary on the chain ending at the ledger's last
//!   posted digest whose balances root is the balances database's, with that close's matrix
//!   ([Close::matrix]). Use [Summary::genesis] with [Matrix::empty] only for a balances database
//!   that never committed a batch. Reopen the payout log at that summary's payouts size and require
//!   its payouts root. Otherwise the validator's attestation matches no honest validator's, or
//!   [Checked::settle] refuses every close.
//!
//! - **V3.** Pass [Close::check] the ledger's queues as final ledger state holds them while the
//!   ledger expects the close. Queues grow only at their tail, so read them again at a later final
//!   block before treating an [Error::InvalidCount] refusal as a rejection. Otherwise the validator
//!   rejects a valid close or credits requests the ledger does not hold.
//!
//! - **V4.** Before releasing an attestation, persist the close, the requests it processes
//!   ([Queue::prefix], in the [Deposit] and [ForcedWithdrawal] encodings), and the proposal's
//!   summary. Checking the close again needs only a queue of exactly that prefix, with each
//!   required count equal to its length. Otherwise, once the close posts and the ledger drops those
//!   requests, a crash leaves the validator unable to apply or serve it.
//!
//! - **V5.** Apply exactly the posted closes, once each, in epoch order, each to databases at its
//!   parent's roots, and no other batch. Otherwise a root diverges, and [Checked::settle] and
//!   [Proposal::apply] refuse with [Error::InvalidCheckpoint] until it recovers by reopening at a
//!   retained posted commit, by replaying persisted posted closes, or by state sync to a posted
//!   root.
//!
//! - **V6.** Keep each posted matrix while receivers may still audit it, and serve openings
//!   ([Matrix::open]). Serve each close and the requests it processes to validators that did not
//!   check it. Keep the whole payout log, and serve payout proofs ([PayoutProof]) under the last
//!   posted payouts root, before and after a halt. After a halt, also serve balance proofs under
//!   the last posted balances root. Otherwise receivers cannot challenge, peers cannot apply the
//!   close, and accounts cannot withdraw their payouts or claim.
//!
//! - **V7.** Decode closes with the deployment's [Limits]. Otherwise the validator rejects valid
//!   closes or attests closes beyond the agreed limits.
//!
//! # The ledger
//!
//! The production ledger is a contract on the chain that holds the funds, with its own storage. The
//! crate supplies the checks that protect funds and specifies the rest. [Summary::verify] checks
//! posts, [Challenge::verify] checks challenges, [PayoutProof::verify] checks payout withdrawals
//! and claims, and [BalanceProof::verify] checks balance claims. The ledger keeps three stores, and
//! the requests and payouts below move through them.
//!
//! ```text
//!                           +------------------------------+
//!                           | queues, oldest first         |-- prefix --> close(e)
//!   deposit --------------->| deposits                     |-- claim, after halt --> account
//!   forced withdrawal ----->| forced withdrawals           |
//!                           +------------------------------+
//!                           +------------------------------+
//!   Summary, certificate -->| posted                       |-- claim, after halt --> account
//!   Challenge ------------->| last digest, balances root   |
//!                           | matrix root of each epoch    |
//!                           | halted or not                |
//!                           +------------------------------+
//!                           +------------------------------+
//!   Summary payouts ------->| payouts root and size        |
//!   PayoutProof ----------->| claimed ranges [0,2) [3,5)   |-- withdraw --> account
//!                           +------------------------------+
//! ```
//!
//! The funds the ledger holds back the balances as of the last post, the deposits still queued, and
//! the posted payouts not yet paid. The ledger counts the funds held as one amount. The last posted
//! roots, the queued deposits, and the claimed ranges determine how much backs each part.
//!
//! ```text
//!                0                                                               largest amount
//!   funds held   |================================|=================|=============|...........|
//!                         balances at the               deposits        payouts        room
//!                            last post                still queued    not yet paid
//! ```
//!
//! A post moves no funds and changes only what they back. Funds enter only by deposit and leave
//! only by withdrawal or claim, so bounding deposits bounds the funds held.
//!
//! ```text
//!   deposit --> queued   --- post --> balances --- post --> unpaid  -- withdraw --> account
//!               deposits   processed               payouts  payouts
//!                  |                      |
//!                  |                      '-- claim with proof, after halt --> account
//!                  '-- claim, after halt --> account
//! ```
//!
//! - **L1.** Start with the digest of [Summary::genesis] over the root of an empty [Balances]
//!   database as the last post, expecting the close of epoch 1, with empty queues, required counts
//!   of zero, and no funds. Otherwise the first summary validators certify names a parent the
//!   ledger refuses.
//!
//! - **L2.** A deposit takes custody of its amount before it is queued. Deposits and forced
//!   withdrawals join the tail of their queue, only before a halt and only with nonzero amounts,
//!   and leave it only as L5 and L8 say. Otherwise a deposit credits funds the ledger does not
//!   hold, or validators and the ledger read different requests for the same counts.
//!
//! - **L3.** Refuse a deposit that would take the funds held past the largest amount. Otherwise a
//!   close can credit a balance past the largest amount, and validators reject it with
//!   [Error::Overflow]. When the excess comes from its rows or a required deposit, no acceptable
//!   close exists, as in O3.
//!
//! - **L4.** Queue a forced withdrawal only on a request its account authenticated. Otherwise
//!   anyone can force an account's balance out and learn the amount.
//!
//! - **L5.** Post only before a halt, and only a summary [Summary::verify] accepts for the expected
//!   epoch, the last post's digest, and each queue's range from its required count to its length.
//!   Otherwise a summary honest validators did not certify can post.
//!
//!   In one state change, a post drops the processed requests and sets each required count to what
//!   remains queued. It adds the commit position (the payouts size less one) to the claimed ranges.
//!   It records the summary's matrix root, balances root, payouts root and size, and digest. It
//!   transfers nothing. A lower required count lets closes defer a forced withdrawal forever, and a
//!   transfer that can fail inside a post blocks every later post.
//!
//! - **L6.** Pay a payout, before or after a halt, only if [PayoutProof::verify] accepts its proof
//!   under the last posted payouts root and no claimed range covers its index. In one state change,
//!   add the index to the claimed ranges and pay the payout to its account's destination (L10).
//!   Otherwise a payout is paid twice or never.
//!
//! - **L7.** Before a halt, halt on a challenge that [Challenge::verify] accepts against a posted
//!   epoch and its matrix root, and keep every posted matrix root. Otherwise receivers lose their
//!   recourse, anyone can halt the ledger, or receipts of a forgotten epoch become unenforceable.
//!
//! - **L8.** Once halted, by a valid challenge or the deployment's own policy, post nothing and
//!   take no deposit or forced withdrawal. Make each queued deposit claimable by its account, and
//!   drop the queued forced withdrawals and the required counts. Unpaid payouts stay claimable
//!   under the last posted payouts root. Otherwise a post after the halt changes the balances
//!   accounts claim against.
//!
//! - **L9.** After a halt, pay each account its balance at most once, only if
//!   [BalanceProof::verify] accepts its proof under the last posted balances root. Pay its
//!   claimable deposits at most once. Otherwise an account claims twice or claims a balance it does
//!   not have.
//!
//! - **L10.** Send every transfer of L6 and L9 to a destination the account fixed through a request
//!   it authenticated, or one derived from its key, never one the caller chooses. Otherwise anyone
//!   holding a balance proof claims another account's balance, because validators may serve proofs
//!   to anyone after a halt.
//!
//! - **L11.** Make every check depend only on the ledger's state and the call's inputs. Otherwise
//!   two replicas of the ledger diverge.
//!
//! After a halt, each account claims its balance, the deposits no close processed, and its payouts.
//! The balance and payout claims need proofs, and a validator supplies them.
//!
//! ```text
//!   validator --balance proof--> account --claim(proof)--> ledger --> balance as of the last post
//!                                account --claim---------> ledger --> deposits no close processed
//!   validator --payout proof---> account --claim(proof)--> ledger --> one payout, once per index
//! ```
//!
//! The ledger tracks paid payouts by their indices in the payout log. Its claimed ranges map each
//! range's start to its exclusive end, begin as [0, 1) over the initial commit, and cover every
//! commit and every paid payout. A withdrawal before a halt, or a claim after one, adds [i, i + 1)
//! for the payout at index i and merges it with the ranges it touches. A post adds its commit
//! position the same way.
//!
//! Ranges never overlap or touch. Every commit is covered, so once every payout is paid the ranges
//! collapse to the one range [0, s) for the last posted payouts size s. Each gap between two ranges
//! holds at least one unpaid payout, so with U payouts unpaid at most U + 1 ranges remain in any
//! order of payment.
//!
//! ```text
//!   log index     0   1   2   3   4   5   6
//!               +---+---+---+---+---+---+---+
//!   operation   | C | C | a | b | C | c | C |     C  commit
//!               +---+---+---+---+---+---+---+     a, b, c  payouts
//!   posted      [=======)       [===)   [===)     [0,2) [4,5) [6,7)
//!   withdraw b  [=======)   [=======)   [===)     [0,2) [3,5) [6,7)
//!   withdraw a  [===================)   [===)     [0,5) [6,7)
//!   withdraw b  refused, a range covers 3
//!   withdraw c  [===========================)     [0,7)
//! ```
//!
//! The proof shows that a payout exists, and the claimed ranges keep it from being paid twice. A
//! replayed proof is refused even though it still verifies. A proof verifies only under the root it
//! was built for, so after a later post the account fetches a fresh proof of the same index.
//!
//! ## What a port reproduces
//!
//! A ledger port reproduces these rules bit for bit. Each is what the crate computes for a post, a
//! challenge, or a claim, so a port checks its results against the crate's before it holds funds.
//!
//! 1. **Integers.** Fixed-width integers (every epoch, count, and built-in amount) encode
//!    big-endian, and lengths encode as varints. Public keys and digests encode as their raw bytes.
//!    The genesis summary's parent and both of its running hashes are all zeros.
//!
//! 2. **Trees.** Payment maps and the matrix commit with the binary Merkle tree of
//!    [commonware_storage::bmt]. A leaf is hashed with its big-endian `u32` position, each level
//!    hashes pairs and duplicates an unpaired last node, and the root is
//!    `H(leaf_count || tree_root)`. An empty tree holds the single node `H()`, so its root is
//!    `H(0u32 || H())`.
//!
//! 3. **Leaves.** A map entry is `H(account || amount)`, and a matrix row is
//!    `H(sender || payments root)`. Entries are strictly increasing by account.
//!
//! 4. **Openings.** A member [Lookup] proves one leaf. A non-member lookup proves the neighbors at
//!    `position - 1` and `position`, with the key strictly between them, and a missing neighbor
//!    means the key precedes the first entry or follows the last. An [Opening] verifies the row
//!    under the matrix root, then the entry under the row's root, and has an entry exactly when the
//!    row exists.
//!
//! 5. **Signatures.** Each scheme's verification defines its framing. An Ed25519 signature covers
//!    the namespace's varint length, the namespace, and the message, and each [Namespace] field is
//!    itself that framing of the deployment's namespace and a fixed suffix.
//!
//! 6. **Receipts.** A [State] encodes as epoch, account, payments root, and previous root. The
//!    sender signs it in [Namespace::state] and the operator in [Namespace::acknowledgement], and
//!    the receipt's entry proves under the state's payments root at its position.
//!
//! 7. **Summaries.** A [Summary] encodes as epoch, parent, matrix, balances, and its [Payouts] as
//!    root and size, then the count and running hash of the deposits and of the forced withdrawals.
//!    Its digest is the hash of that encoding, and the certificate covers the encoding in
//!    [Namespace::summary]. A running hash extends its parent's by `H(hash || request)` for each
//!    request the close processes in queue order. A request encodes as its account then its amount.
//!    The ledger takes the running hashes as certified and does not recompute them.
//!
//! 8. **Counts.** Each count lies between its queue's required count and its length.
//!
//! 9. **The empty roots.** A deployment reads the empty balances root from an empty [Balances]
//!    database. It depends on the hasher, account type, and amount type, because the database pads
//!    its fixed-size operations to the key and value widths. An empty [PayoutLog] holds one commit
//!    with no metadata and an inactivity floor of zero, so its size is 1. [Summary::genesis]
//!    records its root.
//!
//! 10. **Balance proofs.** [BalanceProof::verify] is the key-value proof of QMDB's current
//!     database, an operation proof under the canonical root together with its bitmap chunk. It is
//!     the largest part of a port.
//!
//! 11. **Payout proofs.** [PayoutProof::verify] is the range proof of QMDB's keyless database for
//!     one operation, over the Merkle Mountain Range of [commonware_storage::merkle::mmr]. A leaf
//!     is `H(position || operation)`, with the operation's node position in the range as a
//!     big-endian `u64`. That position differs from the operation's index. The proof rebuilds the
//!     root from that leaf and the log's size. The floor stays zero, so the root has no inactive
//!     peaks.
//!
//!     Every operation encodes to the payout's width plus 10 bytes. An appended payout encodes as
//!     tag 1, its account, its amount, and zeros to that size. A commit encodes as tag 0, a zero
//!     byte for its absent metadata, zeros of the payout's width, and its inactivity floor as a
//!     big-endian `u64`. A port reproduces the storage crate's node and root hashing for that
//!     family.

mod amounts;
mod close;
mod error;
mod lookup;
mod matrix;
mod namespace;
mod payment;
mod settlement;
mod summary;
#[cfg(test)]
mod tests;
mod validator;

pub use amounts::{Amount, Amounts};
pub use close::{Close, Deposit, ForcedWithdrawal, Limits, Queue, Row, Withdrawal};
pub use error::Error;
pub use lookup::Lookup;
pub use matrix::{Matrix, Opening};
pub use namespace::Namespace;
pub use payment::{
    Acknowledgement, Admission, Challenge, Receipt, Request, State, States, Verified,
};
pub use settlement::Flow;
pub use summary::{Payouts, Processed, Summary};
pub use validator::{
    BalanceProof, Balances, Checked, Checkpoint, Payout, PayoutLog, PayoutProof, Proposal,
};

/// An epoch number. Epochs start at one, and epoch zero names the state before the first close.
pub type Epoch = u64;
