//! Payer-owned preparation and the ordered durable payment barrier.

use super::*;
#[cfg(test)]
use crate::operator::rpc::AcceptSendRequest;
use crate::{
    operator::{
        rpc::{AcceptSendsRequest, AcceptSendsResponse, AcceptedBatchResponse},
        verify::{MAX_VERIFICATION_BATCHES, VerifiedSends},
    },
    rpc::MAX_BODY_SIZE,
};
use commonware_clearing::bajillion::payment::VectorSendBody;
use commonware_codec::EncodeSize;
use commonware_parallel::Strategy as _;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) enum SendsVerdict {
    Accepted(Vec<AcceptedBatch>),
    Stale(Endpoint),
}

pub(crate) struct CommittedSends {
    pub(crate) verdicts: Vec<Result<SendsVerdict>>,
    pub(crate) epoch: u64,
    pub(crate) requests: usize,
    pub(crate) entries: usize,
}

struct SequenceInput {
    request: AcceptSendsRequest,
    accepted: Vec<AcceptedBatch>,
    endpoint: Endpoint,
}

struct PreparedSequence {
    request: AcceptSendsRequest,
    accepted: Vec<AcceptedBatch>,
    replayed: usize,
    vector: Vec<OutEntry<Key>>,
    credits: BTreeMap<Key, u64>,
    total: u64,
}

enum Preparation {
    Stale(Endpoint),
    Ready(PreparedSequence),
}

impl Store {
    #[cfg(test)]
    pub(crate) fn accept_send(
        &mut self,
        context: &EpochPaymentContext,
        protocol: &Protocol,
        authorization: SendAuthorization<Key, Digest>,
        entries: &[Entry],
    ) -> Result<SendVerdict> {
        let verified = crate::operator::verify_sends(
            vec![AcceptSendsRequest {
                sends: vec![AcceptSendRequest {
                    authorization,
                    entries: entries.to_vec(),
                }],
            }],
            &mut commonware_utils::test_rng(),
            protocol.strategy(),
        )
        .pop()
        .expect("one submitted batch")?;
        let committed = self.accept_verified_sends(context, protocol, vec![(verified, Ok(()))])?;
        Ok(
            match committed
                .verdicts
                .into_iter()
                .next()
                .expect("one submitted batch")?
            {
                SendsVerdict::Accepted(mut accepted) => {
                    SendVerdict::Accepted(Box::new(accepted.pop().expect("one send")))
                }
                SendsVerdict::Stale(endpoint) => SendVerdict::Stale(endpoint),
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn payment_requires_epoch_registration(
        &self,
        context: &EpochPaymentContext,
        protocol: &Protocol,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
    ) -> Result<bool> {
        let verified = crate::operator::verify_sends(
            vec![AcceptSendsRequest {
                sends: vec![AcceptSendRequest {
                    authorization: authorization.clone(),
                    entries: entries.to_vec(),
                }],
            }],
            &mut commonware_utils::test_rng(),
            protocol.strategy(),
        )
        .pop()
        .expect("one submitted batch")?;
        self.sends_require_epoch_registration(context, protocol, &verified)
    }

    /// Commits each fresh payer suffix in one shared durability barrier.
    pub(crate) fn accept_verified_sends(
        &mut self,
        context: &EpochPaymentContext,
        protocol: &Protocol,
        requests: Vec<(VerifiedSends, Result<()>)>,
    ) -> Result<CommittedSends> {
        ensure!(
            requests.len() <= MAX_VERIFICATION_BATCHES,
            "payment group exceeds the operator bound"
        );
        let mut payers = BTreeSet::new();
        for (request, _) in &requests {
            ensure!(
                payers.insert(
                    request.request().sends[0]
                        .authorization
                        .body()
                        .payer()
                        .clone()
                ),
                "payment group repeats a payer"
            );
        }
        let mut inputs = Vec::new();
        for (request, admission) in requests {
            let input = read_sequence(&self.connection, context, request.into_request());
            propagate_storage_error(&input)?;
            inputs.push((input, admission));
        }
        // Only payer-owned vectors and immutable receipt artifacts are prepared in
        // parallel. Balances and epoch budgets belong to the ordered SQL prefix.
        let prepared = protocol.strategy().map_collect_vec(inputs, |(input, admission)| {
            let prepared = prepare_sequence(context, protocol, input?)?;
            if matches!(&prepared, Preparation::Ready(plan) if plan.replayed < plan.accepted.len()) {
                admission?;
            }
            Ok(prepared)
        });
        let mut committed = CommittedSends {
            verdicts: Vec::with_capacity(prepared.len()),
            epoch: context.epoch(),
            requests: 0,
            entries: 0,
        };
        if !prepared.iter().any(|result| {
            matches!(result, Ok(Preparation::Ready(plan)) if plan.replayed < plan.accepted.len())
        }) {
            committed.verdicts = prepared.into_iter().map(prepared_verdict).collect();
            return Ok(committed);
        }
        #[cfg(test)]
        let fail_write = std::mem::take(&mut self.fail_payment_write);
        #[cfg(test)]
        let fail_commit = std::mem::take(&mut self.fail_payment_commit);
        #[cfg(test)]
        let gate = self.payment_commit_gates.pop_front();
        mutate(&mut self.connection, "payment", |transaction| {
            ensure!(
                metadata_epoch(transaction)? == context.epoch()
                    && metadata_payment_context(transaction)?.as_ref() == Some(context),
                "payment context changed before commit"
            );
            let epoch_sql = sql_u64(context.epoch(), "epoch")?;
            let mut count = epoch_entry_count(transaction, epoch_sql)?;
            let mut gross = epoch_gross(transaction, epoch_sql)?;
            for prepared in prepared {
                let plan = match prepared {
                    Err(error) => {
                        committed.verdicts.push(Err(error));
                        continue;
                    }
                    Ok(Preparation::Stale(endpoint)) => {
                        committed.verdicts.push(Ok(SendsVerdict::Stale(endpoint)));
                        continue;
                    }
                    Ok(Preparation::Ready(plan)) => plan,
                };
                if plan.replayed == plan.accepted.len() {
                    committed
                        .verdicts
                        .push(Ok(SendsVerdict::Accepted(plan.accepted)));
                    continue;
                }
                let fresh_entries = plan.request.sends[plan.replayed..]
                    .iter()
                    .map(|send| send.entries.len())
                    .sum::<usize>();
                let payer_key = plan.request.sends[0].authorization.body().payer();
                let payer = eligible_account(transaction, context.epoch(), payer_key);
                propagate_storage_error(&payer)?;
                let mut receivers = Vec::with_capacity(plan.credits.len());
                for recipient in plan.credits.keys() {
                    receivers.push(
                        match effective_account(transaction, context.epoch(), recipient)? {
                            Some(account) => account,
                            None => StoredAccount {
                                name: account_name(transaction, recipient)?,
                                key: recipient.clone(),
                                predecessor: 0,
                                current: 0,
                            },
                        },
                    );
                }
                let balances = (|| {
                    let mut payer = payer?;
                    ensure!(
                        fresh_entries <= MAX_ACCEPTED_PAYMENTS.saturating_sub(count),
                        "epoch payment capacity is exhausted"
                    );
                    let next_gross = checked_sql_add(gross, plan.total, "epoch gross payment")?;
                    ensure!(
                        payer.current >= plan.total,
                        "payer has insufficient available balance"
                    );
                    payer.current -= plan.total;
                    for receiver in &mut receivers {
                        receiver.current = checked_sql_add(
                            receiver.current,
                            plan.credits[&receiver.key],
                            "receiver account balance",
                        )?;
                    }
                    Ok::<_, anyhow::Error>((payer, next_gross))
                })();
                let (payer, next_gross) = match balances {
                    Ok(value) => value,
                    Err(error) => {
                        committed.verdicts.push(Err(error));
                        continue;
                    }
                };
                write_sequence(transaction, context.epoch(), &plan, &payer, &receivers)?;
                count += fresh_entries;
                gross = next_gross;
                committed.requests += plan.accepted.len() - plan.replayed;
                committed.entries += fresh_entries;
                committed
                    .verdicts
                    .push(Ok(SendsVerdict::Accepted(plan.accepted)));
            }
            #[cfg(test)]
            if committed.requests > 0 {
                if fail_write {
                    return Err(rusqlite::Error::ExecuteReturnedResults.into());
                }
                if let Some((entered, release)) = gate {
                    let _ = entered.send(());
                    release.recv().expect("payment commit gate sender dropped");
                }
            }
            Ok(())
        })?;
        #[cfg(test)]
        if fail_commit && committed.requests > 0 {
            return Err(
                CommitUnknown::new("payment", rusqlite::Error::ExecuteReturnedResults).into(),
            );
        }
        Ok(committed)
    }

    pub(crate) fn sends_require_epoch_registration(
        &self,
        context: &EpochPaymentContext,
        protocol: &Protocol,
        verified: &VerifiedSends,
    ) -> Result<bool> {
        let input = read_sequence(&self.connection, context, verified.request().clone())?;
        let plan = match prepare_sequence(context, protocol, input)? {
            Preparation::Stale(_) => return Ok(false),
            Preparation::Ready(plan) => plan,
        };
        if plan.replayed == plan.accepted.len() {
            return Ok(false);
        }
        let epoch_sql = sql_u64(context.epoch(), "epoch")?;
        let count = epoch_entry_count(&self.connection, epoch_sql)?;
        let entries = plan.request.sends[plan.replayed..]
            .iter()
            .map(|send| send.entries.len())
            .sum::<usize>();
        ensure!(
            entries <= MAX_ACCEPTED_PAYMENTS.saturating_sub(count),
            "epoch payment capacity is exhausted"
        );
        checked_sql_add(
            epoch_gross(&self.connection, epoch_sql)?,
            plan.total,
            "epoch gross payment",
        )?;
        let payer = eligible_account(
            &self.connection,
            context.epoch(),
            plan.request.sends[0].authorization.body().payer(),
        )?;
        ensure!(
            payer.current >= plan.total,
            "payer has insufficient available balance"
        );
        for (recipient, amount) in plan.credits {
            let balance = effective_account(&self.connection, context.epoch(), &recipient)?
                .map_or(0, |account| account.current);
            checked_sql_add(balance, amount, "receiver account balance")?;
        }
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn gate_next_payment_commit(
        &mut self,
        entered: commonware_utils::channel::oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        self.payment_commit_gates.push_back((entered, release));
    }
}

fn propagate_storage_error<T>(result: &Result<T>) -> Result<()> {
    if let Err(error) = result
        && error
            .chain()
            .any(|source| source.downcast_ref::<rusqlite::Error>().is_some())
    {
        return Err(MutationFailed::new("payment group read", anyhow::anyhow!("{error:#}")).into());
    }
    Ok(())
}

fn read_sequence(
    connection: &Connection,
    context: &EpochPaymentContext,
    request: AcceptSendsRequest,
) -> Result<SequenceInput> {
    request.validate()?;
    let mut accepted = Vec::new();
    for send in &request.sends {
        let Some(batch) = find_accepted_batch(connection, &send.authorization, &send.entries)?
        else {
            break;
        };
        accepted.push(batch);
    }
    let epoch = metadata_epoch(connection)?;
    if accepted.len() != request.sends.len() {
        ensure!(epoch == context.epoch(), "payment context is stale");
        ensure!(
            metadata_payment_context(connection)?.as_ref() == Some(context),
            "payment anchor is stale"
        );
    }
    let epoch = sql_u64(epoch, "epoch")?;
    let payer = request.sends[0].authorization.body().payer();
    let (seq, cumulative_debit) = payer_endpoint(connection, epoch, payer)?;
    let entries = out_entries_for(connection, epoch, payer)?;
    Ok(SequenceInput {
        request,
        accepted,
        endpoint: Endpoint {
            seq,
            cumulative_debit,
            entries,
        },
    })
}

fn prepare_sequence(
    context: &EpochPaymentContext,
    protocol: &Protocol,
    input: SequenceInput,
) -> Result<Preparation> {
    let SequenceInput {
        request,
        mut accepted,
        endpoint,
    } = input;
    let replayed = accepted.len();
    let payer = request.sends[0].authorization.body().payer().clone();
    let mut merged = endpoint.entries.clone();
    let mut seq = endpoint.seq;
    let mut debit = endpoint.cumulative_debit;
    let mut total = 0_u64;
    let mut credits = BTreeMap::<Key, u64>::new();
    for send in &request.sends[replayed..] {
        let body = send.authorization.body();
        if VectorSendBody::new(
            context,
            payer.clone(),
            body.seq(),
            body.cumulative_debit(),
            body.send_root(),
        ) != *body
        {
            return Ok(Preparation::Stale(endpoint));
        }
        ensure!(
            send.entries
                .windows(2)
                .all(|pair| pair[0].recipient < pair[1].recipient),
            "batch entries are not strictly recipient-sorted"
        );
        let mut amount = 0_u64;
        for entry in &send.entries {
            ensure!(
                entry.recipient != payer,
                "self-payments are omitted from this operator"
            );
            ensure!(entry.amount > 0, "batch entry amount must be positive");
            amount = checked_sql_add(amount, entry.amount, "batch total")?;
        }
        ensure!(
            body.seq() > seq,
            "batch sequence is already bound to another accepted endpoint"
        );
        seq = seq.checked_add(1).context("batch sequence overflow")?;
        debit = checked_sql_add(debit, amount, "payer cumulative debit")?;
        if body.seq() != seq || body.cumulative_debit() != debit {
            return Ok(Preparation::Stale(endpoint));
        }
        for entry in &send.entries {
            match merged.binary_search_by(|edge| edge.recipient.cmp(&entry.recipient)) {
                Ok(position) => {
                    let edge = &mut merged[position];
                    edge.cumulative =
                        checked_sql_add(edge.cumulative, entry.amount, "edge cumulative credit")?;
                    edge.count = checked_sql_add(edge.count, 1, "edge payment count")?;
                }
                Err(position) => merged.insert(
                    position,
                    OutEntry {
                        recipient: entry.recipient.clone(),
                        cumulative: entry.amount,
                        count: 1,
                    },
                ),
            }
            let credit = credits.entry(entry.recipient.clone()).or_default();
            *credit = checked_sql_add(*credit, entry.amount, "batch recipient credit")?;
        }
        ensure!(
            merged.len() <= MAX_ENTRIES,
            "payer vector capacity is exhausted"
        );
        let vector = OutVector::new(context.epoch(), payer.clone(), merged.clone())
            .context("assemble merged out vector")?;
        let tree = vector
            .commitment::<Sha256, Digest>()
            .context("commit merged out vector")?;
        if tree.root() != body.send_root() {
            return Ok(Preparation::Stale(endpoint));
        }
        let operator_signature = protocol
            .operator()
            .sign(VECTOR_ACK_SIGNATURE_NAMESPACE, body.encode().as_ref());
        let ack = Ack::from_raw_unchecked(
            body.clone(),
            send.authorization.payer_signature().clone(),
            operator_signature,
        );
        let mut entries = Vec::with_capacity(send.entries.len());
        for entry in &send.entries {
            let position = merged
                .binary_search_by(|edge| edge.recipient.cmp(&entry.recipient))
                .expect("accepted recipient is in the payer vector");
            let edge = &merged[position];
            let opening = tree
                .opening(u32::try_from(position)?)
                .context("open accepted entry")?;
            ensure!(
                opening.encode_size() <= MAX_OPENING_BYTES,
                "entry opening exceeds the operator bound"
            );
            entries.push(AcceptedEntry {
                recipient: entry.recipient.clone(),
                cumulative: edge.cumulative,
                count: edge.count,
                opening,
            });
        }
        total = checked_sql_add(total, amount, "payer batch total")?;
        accepted.push(AcceptedBatch {
            epoch: context.epoch(),
            sequence: seq,
            total: amount,
            acceptance: Acceptance { ack, entries },
        });
    }
    let response = AcceptSendsResponse::Accepted(
        accepted
            .iter()
            .cloned()
            .map(AcceptedBatchResponse::from)
            .collect(),
    );
    ensure!(
        response.encode_size() <= MAX_BODY_SIZE,
        "accepted sends response exceeds the RPC body bound"
    );
    Ok(Preparation::Ready(PreparedSequence {
        request,
        accepted,
        replayed,
        vector: merged,
        credits,
        total,
    }))
}

fn prepared_verdict(prepared: Result<Preparation>) -> Result<SendsVerdict> {
    Ok(match prepared? {
        Preparation::Stale(endpoint) => SendsVerdict::Stale(endpoint),
        Preparation::Ready(plan) => SendsVerdict::Accepted(plan.accepted),
    })
}

fn epoch_gross(connection: &Connection, epoch: i64) -> Result<u64> {
    let gross = connection
        .prepare_cached("SELECT COALESCE(SUM(cumulative), 0) FROM out_entries WHERE epoch = ?1")?
        .query_row([epoch], |row| row.get::<_, i64>(0))?;
    from_sql_u64(gross, "epoch gross payment")
}

fn write_sequence(
    transaction: &Transaction<'_>,
    epoch: u64,
    plan: &PreparedSequence,
    payer: &StoredAccount,
    receivers: &[StoredAccount],
) -> Result<()> {
    let epoch_sql = sql_u64(epoch, "epoch")?;
    upsert_account_state(transaction, epoch, payer)?;
    for receiver in receivers {
        upsert_account_state(transaction, epoch, receiver)?;
    }
    let mut insert_ack = transaction.prepare_cached(
        "INSERT INTO acks(epoch, payer, seq, cumulative_debit, ack) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut insert_entry = transaction.prepare_cached(
        "INSERT INTO accepted_entries(epoch, payer, seq, recipient, amount, cumulative, count, opening)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for (send, accepted) in plan.request.sends[plan.replayed..]
        .iter()
        .zip(&plan.accepted[plan.replayed..])
    {
        let seq = sql_u64(accepted.sequence, "batch sequence")?;
        let ack = &accepted.acceptance.ack;
        insert_ack.execute(params![
            epoch_sql,
            payer.key.as_ref(),
            seq,
            sql_u64(ack.body().cumulative_debit(), "cumulative debit")?,
            ack.encode().as_ref()
        ])?;
        for (delta, entry) in send.entries.iter().zip(&accepted.acceptance.entries) {
            insert_entry.execute(params![
                epoch_sql,
                payer.key.as_ref(),
                seq,
                entry.recipient.as_ref(),
                sql_u64(delta.amount, "entry amount")?,
                sql_u64(entry.cumulative, "entry cumulative")?,
                sql_u64(entry.count, "entry count")?,
                entry.opening.encode().as_ref()
            ])?;
        }
    }
    let mut advance_edge = transaction.prepare_cached(
        "INSERT INTO out_entries(epoch, payer, recipient, cumulative, count) VALUES(?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(epoch, payer, recipient) DO UPDATE SET cumulative = excluded.cumulative, count = excluded.count",
    )?;
    for entry in &plan.vector {
        if plan.credits.contains_key(&entry.recipient) {
            advance_edge.execute(params![
                epoch_sql,
                payer.key.as_ref(),
                entry.recipient.as_ref(),
                sql_u64(entry.cumulative, "edge cumulative credit")?,
                sql_u64(entry.count, "edge payment count")?
            ])?;
        }
    }
    Ok(())
}
