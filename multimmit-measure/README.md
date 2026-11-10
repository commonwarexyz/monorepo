# Multimmit measurement: reproduction notes

These notes and tools rerun the paper's Multimmit measurements: 90 accepted runs on two 50-validator AWS
testbeds, all from one source revision (this repository without this folder). BlueBottle and Raptr are not
rerun; the paper uses their published results.

| | |
|---|---|
| Testbeds | **global**: 50 x c8g.12xlarge round-robin over 13 regions (us-east-1, us-west-2, ca-central-1, eu-central-1, eu-west-1/2/3, eu-north-1, ap-south-1, ap-southeast-1/2, ap-northeast-1/2). **na**: 50 x c8g.12xlarge round-robin over us-east-1, us-east-2, ca-central-1. Each validator has a 1,000 GiB io2 volume at 16,000 IOPS; one c8g.8xlarge monitor (Prometheus, Loki, Grafana) per testbed |
| Modes | `base`: 50 chains, pipeline depth d = 32, extension bound e = 8. `payments`: every chain a payment chain, d = 0, e = 0, pipeline window 32. `base-fsync`: base with storage sync barriers on (every other mode builds with `unsafe-disable-sync`) |
| Scenarios | `healthy`; `crash1` (node 13 global, node 3 na); `crash9` (nodes 13-21 global, 3-11 na); `loss0.1` (each protocol message dropped with probability 0.001 at the receiver); `censor{1,9}-e{8,0}` (1 or 9 of those nodes lead as censors against victim chains 26, 29, 33, 35, 36 global or 12-16 na, with e = 8 or 0) |
| Rates | 50k, 100k, 250k, 500k, 1M tx/s (512-byte transactions, 512 per 256 KiB block) |
| Matrix | per testbed: base and payments x 4 scenarios x 5 rates (40), censorship x 4 at 500k, base-fsync healthy 500k. The 100k censorship runs the driver also lists were not measured (step 7) |

Run IDs are `<testbed>.<mode>.<scenario>.<rate>`, for example `global.payments.crash9.1M`.

## 1. Source

The measured source is this repository without the `multimmit-measure/` folder. In a git checkout:

```sh
git ls-tree HEAD | grep -v "	multimmit-measure$" | git mktree   # prints 18424c2a0b098606d7ecf805d18844174eecdc02
```

Relative to the measurement base of the paper's first evaluation, the source adds batched marshal inputs, an
`unsafe-disable-sync` runtime feature, a lossy receiver, a censoring proposal policy, and loss, censorship
and signing instrumentation in `examples/log-multimmit`.

All commands below run from the repository root unless they `cd`.

## 2. Build

The validators run Graviton (aarch64). Build in `rust:1.95-bookworm` for linux/arm64 (native on an arm64 host,
emulated and slow elsewhere), from the repository root:

```sh
mkdir -p /tmp/mm-out
docker run --rm --platform linux/arm64 -v "$PWD":/src -v /tmp/mm-out:/out -v mm-target:/target \
  -w /src -e CARGO_TARGET_DIR=/target rust:1.95-bookworm bash /src/multimmit-measure/build.sh
```

This builds `commonware-log-multimmit` three times with `--profile release-with-debug --locked`,
`RUSTFLAGS='-C force-frame-pointers=yes -C target-cpu=generic'`, line-tables-only debug info, stripped:

| Mode | Features | sha256 of the measured binary |
|---|---|---|
| `base` | `unsafe-disable-sync` | `77d86be93376380d629a262ca2fa0d5dd9547ab95f787cce0c26ac661be6e37b` |
| `payments` | `payments,unsafe-disable-sync` | `6dbc0ae08d9eff59080bad4be503d8af0c9bc12b78a89378a522da76dd66c0a1` |
| `base-fsync` | none | `48538847655890e1dba81ed476b2092cab804e54e04005245099a5674b860791` |

Your hashes may differ (build paths and environment); the tree hash is the identity that matters. Also build,
for the machine that drives the campaign:

```sh
cargo build --release -p commonware-deployer --features aws     # target/release/deployer
cargo build --release -p commonware-log-multimmit               # target/release/commonware-log-multimmit (for its deploy subcommand)
```

## 3. Campaign directory

Python 3.9+ with `pyyaml`, the AWS CLI, `ssh`, `zstd`. Then:

```sh
bash multimmit-measure/layout.sh ~/mm
```

`layout.sh` creates `tools/` (driver and analysis), `status/` (progress state and a live `plan.html`),
`provenance/source.json` (commit, and the tree without this folder), `build/`, `testbeds/` and `runs/`.

## 4. Binaries and their hashes

```sh
for m in base payments base-fsync; do mkdir -p ~/mm/build/$m; cp /tmp/mm-out/$m/commonware-log-multimmit ~/mm/build/$m/; done
cp target/release/deployer ~/mm/build/deployer
python3 - <<'EOF'
import hashlib, json, os
ar = os.path.expanduser("~/mm"); feats = {"base": "unsafe-disable-sync", "payments": "payments,unsafe-disable-sync", "base-fsync": ""}
json.dump({m: {"sha256": hashlib.sha256(open(f"{ar}/build/{m}/commonware-log-multimmit", "rb").read()).hexdigest(),
               "features": f, "build": "rust:1.95-bookworm, see build.sh"} for m, f in feats.items()},
          open(f"{ar}/provenance/binaries.json", "w"), indent=1)
EOF
```

Every run checks the binary on every node against `provenance/binaries.json` before it starts.

## 5. Deployment bundles

```sh
bash ~/mm/tools/bundle.sh ~/mm target/release/commonware-log-multimmit
```

This writes `testbeds/{global,na}/deploy/`: the deployer's `config.yaml` (a fresh `tag`, the instances above,
`node-<i>.yaml` configs with 16 worker and 24 compute threads, 256 KiB bodies, d = 32, e = 8, 12 GiB marshal
memory, tracing off) and an idle benchmark schedule. The driver writes each run's own configuration: mode
pipeline settings, a fresh committee seed, the input schedule and faults.

## 6. Clusters

```sh
export AWS_PROFILE=<profile>      # EC2 and S3 rights in all 14 regions; c8g quota for 51 instances per testbed
for tb in global na; do
  bash ~/mm/tools/create.sh $tb                                  # deployer aws create, about 5 min
  python3 ~/mm/tools/discover.py $tb                             # testbeds/<tb>/hosts.json from EC2
  bash ~/mm/tools/stage.sh $tb                                   # binaries to the deployer's S3 bucket, presigned
  python3 ~/mm/tools/campaign.py setup $tb --presigned ~/mm/testbeds/$tb/presigned.json   # to every node, hash-checked
  python3 ~/mm/tools/campaign.py check $tb                       # preflight: binaries, disk, clocks
done
```

The deployer keeps each deployment's ssh key under `~/.commonware_deployer/<tag>/`; the driver uses it.
Every node is reached by its public IP; node `i` is participant `i`.

## 7. Run

```sh
cd ~/mm && python3 status/status.py init
for tb in global na; do for c in censor1-e8 censor1-e0 censor9-e8 censor9-e0; do
  python3 status/status.py run $tb.base.$c.100k skipped --reason "censorship measured at 500k only"; done; done
for tb in global na; do python3 tools/detach.py testbeds/$tb/driver.out python3 tools/campaign.py run $tb; done
```

One detached driver per testbed works through its queue, hardest first: the 1M point of every scenario, the
500k censorship runs, the remaining points from 500k down to 50k, and fsync. A run takes 6-7 minutes, so each
testbed needs about 5 hours. Follow `plan.html` (rebuilt after every phase), `status/progress.json`,
`testbeds/<tb>/driver.out`, and each attempt's `driver.log`. A file named `testbeds/<tb>/STOP` stops that
driver between runs; starting it again resumes the queue.

### What one run does

1. **Preflight**: stop every validator, wipe data and logs, check binary hashes, free disk, and clocks
   (within 2 ms; chrony).
2. **Configure**: a fresh committee seed (sha256 of run ID and attempt); a fixed input schedule at the run's rate,
   split evenly over the live producers; faults for the scenario. Crashed nodes are never started; nodes 0 and 1
   (bootstrappers) are never faulted.
3. **Warm-up and gate**: load starts 45 s after launch. At 120 s the gate checks the last three 10 s windows of
   scrapes: placed throughput at least 95% of offered (no window under 80%), input-queue P99 under 1 s and the
   unplaced backlog not growing, placement P50 within +/-15% and P99 not rising, views advancing and close,
   nullifications not trending up, memory under 85%, no new ERROR lines, and every live producer building at
   least 90% of its schedule. A failure extends the warm-up by 60 s, at most twice.
4. **Cohort**: the blocks whose scheduled submission falls in the next 120 s.
5. **Drain**: until every live producer has delivered every cohort block, at most 120 s.
6. **Collect and analyse**: per-node benchmark events, warnings, final metrics, Prometheus queries, clocks;
   `analyze.py` writes `result.json` with a verdict.
7. **Verdict**: *accepted* needs a steady gate, the whole cohort placed and delivered, at least 95% of the offered
   rate placed, the expected validators live, bounded backlog, per-producer accounting within 1.5 blocks,
   clocks within 2 ms before and after, complete telemetry, and for loss runs, loss injected on every node.
   Infrastructure faults are retried from a wipe; two in a row pause the testbed. Each node's TCP
   retransmission share is recorded and reported, not used to reject a run.

### Notes

- **Global 1M**: each validator then sends about 4.8 Gbit/s to its 49 peers. At times validators outside Europe
  lose 10-30% of their TCP segments on every path, with no host-side drops. Those runs pass every check and
  are kept; `result.json` names the affected validators under `network`.
- **Payment chains** need `pipeline_window` to cover the DA-certificate lag at the block rate: 39 blocks/s per
  producer at 1M and up to ~520 ms of lag from Sydney and Seoul. Window 16 starves those producers; 32 does not.
- **Censorship**: leaders rotate round-robin (participant `view mod 50` leads), so the 9 censors lead 9
  consecutive views of every 50, followed by an honest leader. `result.json` reports placement over all victim
  blocks and, under `censorship.censored_views`, over only the victim blocks a censor's view would have placed
  (the view in which the other chains' blocks submitted within 25 ms were first finalized), against the other
  chains' blocks finalized in those views. The paper uses the censored views.

## 8. Definitions

- **Latency** of a block: from its scheduled submission to the milestone at its producer, on that machine's clock.
  Every transaction of a block shares its latency. **Placement** (headline): the block's position in the total
  order is fixed; the earlier of the engine's placement event and ordered delivery. Also: first finality,
  ordered delivery, DA certificate (32 of 50), receipt (41 of 50, payment chains).
- **Achieved throughput**: cohort transactions placed per second of the 120 s cohort.
- **Traffic**: Prometheus rates summed across validators over the cohort; consensus traffic is
  `engine_voter_transmitted_bytes_total` by plane, application traffic is `runtime_outbound_bandwidth_total`.

## 9. After the runs

```sh
cd ~/mm
python3 tools/reanalyze.py global && python3 tools/reanalyze.py na   # every attempt with the final analysis; keeps result.driver.json
python3 tools/build_summary.py                                     # summary.json.zst and manifest.json (sha256 of every file)
for tb in global na; do for s in prometheus loki; do bash tools/pull_store.sh $tb $s; done; done   # whole stores, before teardown
```

To include the published BlueBottle and Raptr records in the summary, put them in `provenance/published.json`
first. `pull_store.sh` pauses the container for the copy: the monitor recreates a stopped monitoring container at
once, so a stop does not give a consistent copy.

## 10. Teardown

```sh
for tb in global na; do (cd ~/mm/testbeds/$tb/deploy && ~/mm/build/deployer aws destroy --config config.yaml); done
```

Then confirm nothing tagged with either deployment tag remains in any of the 14 regions (instances, volumes,
VPCs, security groups, key pairs) and that the deployment prefixes in the deployer's S3 bucket are empty.

## Cost

Network traffic dominates, not compute: the validators talk over public IPs, so traffic between regions
($0.02-0.09/GB) and within a region ($0.01/GB each way) is billed. A global 1M run moves about 27 GB/s across
the testbed. The full matrix with its retries moved about 0.9 PB; expect tens of thousands of dollars.
Activate the deployer's `deployer` tag for cost allocation to attribute spend per cluster.
