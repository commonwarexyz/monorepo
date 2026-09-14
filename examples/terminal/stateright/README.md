# Native withdrawal lifecycle

This model checks withdrawals across the operator's durable storage and the
settlement chain. It exercises registration, delayed observations, exact retries,
and restart around publication and claims.

Run from the workspace root:

```bash
just test -p commonware-terminal --lib withdrawal_model
just test -p commonware-terminal --lib service::lifecycle
```

## Withdrawal flow

```text
Wallet                    Operator                  Settlement
  |--- signed request ------>|                          |
  |                          | persist request          |
  |<-- original ack ---------|                          |
  |                          |--- registration -------->|
  |                          |                          | admit / finalize
  |                          |<--- certified reads -----|
  |--- withdrawal claim ------------------------------->|
  |<--------------------------------------- release ----|
  |--- acknowledge --------->| retire claim evidence    |
```

A wallet can also queue its signed request directly with settlement for the next
registration. The model tracks chain acceptance separately from the operator's
view, allowing responses and certified reads to arrive after the chain advances.

Certified observations determine whether the operator retains a request or
releases a stale reservation. Restart preserves stored requests, original
acknowledgments, and claim state. A payout and the operator's acknowledgment of
it are separate durable steps.

## What the tests do

[withdrawal.rs](withdrawal.rs) explores every reachable state of small fixtures
with Amount and Close withdrawals, changing balances, and finite epochs. The
[replay tests](../src/service/lifecycle.rs) execute a required set of generated
traces through the real service, SQLite storage, and certified chain-query
harness, comparing results and retained state after each action.

The fixtures assume timely settlement. Reconciliation can pause around certified
reads while the chain advances; retries and restarts must preserve accepted
requests and release each output at most once.
