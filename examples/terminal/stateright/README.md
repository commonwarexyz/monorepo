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

While the live epoch is unpublished, intake stages into it and the operator
acknowledges once the request persists:

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

A published live boundary stages no intake until the live epoch adopts its
certified registration. From then on, intake stages into the successor as an
authorization that reserves nothing. The operator acknowledges only after the
successor registers and the certified handoff installs it:

```text
Wallet                    Operator                  Settlement
  |--- signed request ------>|                          |
  |                          | persist authorization    |
  |                          |--- register successor -->|
  |                          |<--- certified record ----|
  |                          | handoff                  |
  |<-- original ack ---------|                          |
```

A wallet can also queue its signed request directly with settlement. The request
waits in the settlement inbox, and the registration that pulls its index must
carry it verbatim unless an earlier registration carried it or superseded it. A
registration whose pull ends before that index may carry it early, or carry
another request for the account, which supersedes it.
The model tracks chain acceptance separately from the operator's view, allowing
responses and certified reads to arrive after the chain advances.

Certified observations determine whether the operator keeps a request or
discards an authorization whose notice window has closed, restoring any
reservation. The wallet's discard of such a request is outside the model.
Restart preserves stored requests, original acknowledgments, and claim state. A
payout and the operator's acknowledgment of it are separate durable steps.

## What the tests do

[withdrawal.rs](withdrawal.rs) explores every reachable state of small fixtures
with Amount and Close withdrawals, changing balances, and finite epochs. The
[replay tests](../src/service/lifecycle.rs) execute a required set of generated
traces through the real service, SQLite storage, and certified chain-query
harness, comparing results and retained state after each action.

The fixtures assume timely settlement. Reconciliation can pause around certified
reads while the chain advances. Retries and restarts must preserve accepted
requests and release each output at most once. At most one cut close awaits
admission, and operator inbox observation with the pulls it drives is outside
the model.
