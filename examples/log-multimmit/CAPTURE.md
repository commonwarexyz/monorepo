# B-lambda experiment capture

Use the same binary and diagnostic settings for both arms. Leave
`vote_pacing_enabled: false` for the baseline. Enable it for the sweep and set
`vote_pacing_lambda` to 0.7, 0.8, 0.9, or 1.0. These keys belong in the deployed
node configuration's `tuning` section. The equivalent CLI flags are
`--vote-pacing-enabled`, `--vote-pacing-lambda`, and
`--vote-pacing-matrix-ms` (a JSON or YAML nested array).

The matrix contains estimated one-way delays in milliseconds, with rows and
columns in participant order. Save the matrix, its measurement procedure, node
roster, exact revision, workload schedule, and clock synchronization measurements
with each run. RTT/2 is an estimate, not a measured one-way delay. The optional
`vote_pacing_cap_ms` defaults to twice the median off-diagonal matrix entry.

For voter q, pacing waits `lambda * max(0, Q0 - d[L][q] - d[q][N])` after proposal
receipt, capped as above. L is the current leader, N the next leader, and Q0 the
quorum order statistic of those two-leg sums. Verification consumes this interval;
it does not start a second wait. Protocol timeout and rescue retain control.

## Capture each node

Add these runtime flags to every node, including nodes started with `--config`:

```text
--diagnostic-file /persistent/run-id/node-id.jsonl
--diagnostic-warmup-secs 60
--diagnostic-cohort-secs 20
--diagnostic-drain-secs 30
```

Use a fresh file for each process. Capture starts at process startup and closes
automatically after these intervals. Startup skew reduces the common cohort:
start nodes close together and require at least ten seconds of overlap. Increase
warmup if the workload has not reached steady state. Continue the workload through
the cohort; retain drain observations and report unresolved blocks rather than
dropping them. The diagnostic phase labels do not control the workload generator.

The file includes a node configuration event, a process capture identity, local
monotonic timestamps, periodic wall-clock anchors, and a terminal loss summary.
Missing footer, any dropped record, or omitted oversized artifact makes the capture
incomplete. Recording is nonblocking, with an 8192-record queue and a 64 MiB queued
byte limit. Validate capture completeness on the actual workload before accepting
an experiment. Instrumentation can change timings; both arms must use it.

## Read the data

```bash
python3 tools/analyze_capture.py /persistent/run-id/*.jsonl \
  --nodes 0,1,2,3,4,5 --minimum-seconds 10 --output /persistent/run-id/analysis
```

Replace `--nodes` with the full expected participant-key list. The checker exports
`events.csv`, `blocks.csv`, `views.csv`, and `summary.json`. It rejects incomplete transport and
insufficient overlap. Block rows retain missing outcomes. A complete file is not
proof that every cohort block completed; check the missing-event counts separately.
Producer-local blocks need not have a network receipt event.

The event stream records construction and submission, header receipt, validation,
eligibility, complete signed vote identities, body construction, frame preparation
and p2p acceptance, direct pool changes and finalized tips, authenticated history
openings, planned ordering positions, durable ordering checkpoints, and delivery.
Proposal and vote artifacts retain canonical encodings for deeper reconstruction.
Match artifacts by digest and epochs/views, never by timestamps alone.

`blocks.csv` joins constructed endorsements to signed vote bodies and the first
p2p acceptance of their frame. Acceptance is not remote receipt. Finality follows
exact captured ancestry; historical finality is timestamped at validated marshal
history opening, which can follow the earliest consensus evidence. The raw proof,
pool, and history events remain available to separate that processing delay.
Planned ordering is distinct from durable ordering and application delivery.

For latency analysis, use the same submission cohort and transaction weighting in
both arms. Compare finality, placement, and delivery distributions alongside view
durations, waits, and endorsement support. Do not interpret a change in path shares
as a count of transactions saving one whole view. Wall-clock anchors do not remove
cross-node clock error; retain NTP/chrony offset bounds when estimating transit.
