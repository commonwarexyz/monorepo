# Measurement protocol and reproduction

The decision addressed here is whether coalescing merits further investigation
in the ordinary Tokio storage backend. The experiment compares three fixed
policies while preserving input contents, completed work, concurrency, and the
backend's selected synchronization contract.

## Use the archived experiment checkout

This document and the results report do not include the benchmark source or
raw data. The complete experiment is preserved in the author's fork at commit
`918838255e1d4bf106356e1d16118c28506467cc`.

Start a separate checkout before running any command below:

```bash
git clone --no-checkout https://github.com/diegomrsantos/monorepo.git monorepo-write-coalescing
cd monorepo-write-coalescing
git checkout --detach 918838255e1d4bf106356e1d16118c28506467cc
```

All commands below run from the root of that archive checkout, not from an
upstream checkout containing only these documents. The archived Rust sources,
plans, and data retain the identities recorded in the build manifests.

## Policies and workloads

[build_backends.py](https://github.com/diegomrsantos/monorepo/blob/918838255e1d4bf106356e1d16118c28506467cc/experiments/write-coalescing/build_backends.py) builds the unchanged backend and two
experimental variants. Heap coalescing calls `IoBufs::coalesce()` inside the
existing blocking closure. Pool coalescing calls `coalesce_with_pool()` at the
same location and captures the storage pool. The helper records exact patches,
source hashes, build commands, and executable hashes, and restores the original
backend in a `finally` block. Run it in a disposable checkout.

All matrix commands pass `--strategy vectored` to the harness. The chosen
binary supplies the policy, so the caller does not perform another coalescing
step. Allocation, copying, destruction, and pool return remain inside timing.

| Dimension | Frozen main plan |
| --- | --- |
| Total bytes per write | 4096, 65536, 1048576 |
| Nonempty fragments | 1, 8, 32, 128, 256, 1024, 1025 |
| Main source layout | One allocation divided into nearly equal borrowed slices |
| Concurrency | One caller with one outstanding write |
| File | 64 MiB, populated and synchronized before cyclic overwrites |
| Trial | Fresh process, 200 ms warmup, requested 1000 ms measured interval |
| Repetitions | Seven per case and variant |
| Separation | 250 ms between trials |

The 21 primary cases use buffered completion. Six controls synchronize each
write, three use separate allocations for fragments, and two rotate through
16 MiB of input. The [main plan](https://github.com/diegomrsantos/monorepo/blob/918838255e1d4bf106356e1d16118c28506467cc/experiments/write-coalescing/plans/backend-grid.json) contains all 32 cases.
The [smoke plan](https://github.com/diegomrsantos/monorepo/blob/918838255e1d4bf106356e1d16118c28506467cc/experiments/write-coalescing/plans/backend-smoke.json) covers the same cases with shorter
runs. The [baseline pilot](https://github.com/diegomrsantos/monorepo/blob/918838255e1d4bf106356e1d16118c28506467cc/experiments/write-coalescing/plans/backend-aa.json) compares the identical
baseline executable under two labels in six blocks for each of three cases.

Each measured operation clones its prepared fragment list, awaits the real
`Blob::write_at`, and drops its buffers. Source generation and file preparation
precede timing. Warmup uses different contents and finishes with synchronization.
Final synchronization and readback follow timing for buffered cases. In
synchronized cases, each measured write awaits the existing sync contract.

Completed bytes are divided by actual elapsed time, including deadline
overshoot. Process CPU time covers all process threads. Source cloning is a
common cost that a producer transferring ownership might avoid.

## Audit and analyze the existing measurements

Run from the repository root. Python's standard library is sufficient for the
audit and analysis. No benchmark executable or rented machine is needed.

```bash
experiment=experiments/write-coalescing
output=$(mktemp -d)

python3 "$experiment/check_archives.py" . "$output/archive-audit.json"

python3 "$experiment/validate_native.py" \
  "$experiment/results/native/linux/grid.jsonl" \
  --plan "$experiment/plans/backend-grid.json" \
  --manifest "$experiment/results/native/linux/binaries/manifest.json" \
  --repo . --output "$output/linux-validation.json"
python3 "$experiment/validate_native.py" \
  "$experiment/results/native/macos/grid.jsonl" \
  --plan "$experiment/plans/backend-grid.json" \
  --manifest "$experiment/results/native/macos/manifest.json" \
  --repo . --output "$output/macos-validation.json"

python3 "$experiment/analyze_native.py" \
  "$experiment/results/native/linux/grid.jsonl" \
  --output "$output/linux-summary.json"
python3 "$experiment/analyze_native.py" \
  "$experiment/results/native/macos/grid.jsonl" \
  --output "$output/macos-summary.json"

python3 -m unittest discover -s "$experiment" -p 'test_*.py'
rustc +1.98.0 --edition=2024 --test \
  runtime/src/storage/benches/coalescing_checks.rs \
  -o "$output/coalescing-checks"
"$output/coalescing-checks"
```

[check_archives.py](https://github.com/diegomrsantos/monorepo/blob/918838255e1d4bf106356e1d16118c28506467cc/experiments/write-coalescing/check_archives.py) audits all nine retained datasets, covering
1,716 trials, 143 paired comparisons, the main grids' measured source hashes,
all six experimental patch hashes, and the inventory of 180 archived Linux
correctness cases. It selects the matching manifest for each dataset, including
the earlier macOS pilot. Its JSON output records each checked patch and manifest.
The correctness audit checks retained records; it does not rerun fault injection.

The complete archive command requires the measured sources and dependency
lockfile. The individual validator's optional `--repo` check expects those same
files. The source files and runtime manifest supplied with this experiment
match that record. After a source change, retain the measured revision for the
complete audit, or use the individual validator without `--repo` to audit only
the recorded data. Never relabel historical measurements as results for a
different revision.

The audit expects a complete uniform plan with one writer. The main grid, smoke
plan, and baseline pilot have that contract. Separate paged fixtures exercise
correctness through the real paged writer.

[analyze_native.py](https://github.com/diegomrsantos/monorepo/blob/918838255e1d4bf106356e1d16118c28506467cc/experiments/write-coalescing/analyze_native.py) reports geometric means of paired ratios,
with each candidate value divided by its baseline value, and percentile 95%
bootstrap intervals from 10,000 resamples of paired blocks. Analyze each platform
separately. Absolute rates
are medians; their quotient is not the paired estimator. Fewer than five blocks
produce an estimate without a confidence interval.

[render_native.py](https://github.com/diegomrsantos/monorepo/blob/918838255e1d4bf106356e1d16118c28506467cc/experiments/write-coalescing/render_native.py) regenerates the complete grid's table and
figures from the platform summaries. It targets the seven repetition main grid.
Its plotting dependency is Matplotlib; the archived figure used version 3.11.1.
The raw measurements and numerical analysis do not require Matplotlib.

## Build and collect a new comparison

Use Rust 1.98.0 and locked dependencies. The harness follows the existing
standalone storage benchmark pattern. It measures completed I/O over its own
interval, independently of Criterion dashboard output.

Set `work` to a new directory on the filesystem to measure. The 64 MiB fixture
and rotating sources are bounded, but compiler output needs several GiB.
Record hardware, filesystem, storage, power, CPU placement, and background
activity. Use consistent affinity for all commands when applying a CPU mask.

```bash
experiment=experiments/write-coalescing
work=/absolute/path/on/the/filesystem/to/measure
mkdir -p "$work/data"

python3 "$experiment/build_backends.py" --output "$work/binaries"
python3 "$experiment/capture_native.py" \
  --data-root "$work/data" --output "$work/environment-before.json"

python3 "$experiment/run_matrix.py" \
  --binary "$work/binaries/vectored" --binary-dir "$work/binaries" \
  --plan "$experiment/plans/backend-smoke.json" \
  --data-root "$work/data" --output "$work/smoke.jsonl"
python3 "$experiment/run_matrix.py" \
  --binary "$work/binaries/vectored" --binary-dir "$work/binaries" \
  --plan "$experiment/plans/backend-aa.json" \
  --data-root "$work/data" --output "$work/aa.jsonl"
python3 "$experiment/analyze_native.py" "$work/aa.jsonl" \
  --output "$work/aa-summary.json"
```

Inspect the pilot before the full grid. Unexpected drift warrants investigation;
retain every pilot and document any environment change. The main plan has a
fixed repetition budget independent of whether coalescing looks favorable.

```bash
python3 "$experiment/run_matrix.py" \
  --binary "$work/binaries/vectored" --binary-dir "$work/binaries" \
  --plan "$experiment/plans/backend-grid.json" \
  --data-root "$work/data" --output "$work/grid.jsonl"
python3 "$experiment/capture_native.py" \
  --data-root "$work/data" --output "$work/environment-after.json"
python3 "$experiment/validate_native.py" "$work/grid.jsonl" \
  --plan "$experiment/plans/backend-grid.json" \
  --manifest "$work/binaries/manifest.json" \
  --repo . --output "$work/validation.json"
python3 "$experiment/analyze_native.py" "$work/grid.jsonl" \
  --output "$work/summary.json"
```

The runner refuses to overwrite a result file. Preserve raw trials and use a
new output directory for each repetition of the experiment. The recorded Linux
CPU placement and frozen RAID resynchronization are properties of that run,
not generic preparation requirements.

## Separate correctness diagnostics

The Linux interposer injects missing, short, interrupted, and zero progress
writes into paged fixtures and observes synchronization calls. Run it before
performance measurement, using disposable data:

```bash
cc -shared -fPIC -O2 "$experiment/check_io.c" -ldl -o "$work/check_io.so"
for variant in vectored coalesce pool; do
  python3 "$experiment/check_harness.py" \
    --binary "$work/binaries/$variant" --strategy vectored \
    --data-root "$work/data" --io-check "$work/check_io.so" \
    --output "$work/$variant-correctness.json"
done
```

On macOS, omit `--io-check` to run the normal paged checks. The uniform smoke
matrix checks the measured input shapes on both platforms. Never set
`LD_PRELOAD` or `COMMONWARE_IO_FAULT` during performance measurement.
These checks verify bytes and exercised syscall behavior; they are not power
failure tests.
