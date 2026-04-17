# Simplex consensus specification: quint specs, trace validation,
# model-based testing, model-based fuzzing, tlc-controlled.
#
# Domain targets live in make/*.mk; this file holds shared variables.

# Trace validation (tv)
FUZZ_TRACES_ROOT ?= ../fuzz/artifacts/traces
FUZZ_CORPUS ?= ../fuzz/corpus
TRACES_DIR ?= traces
FUZZ_RUNS ?= -1

# Selection strategy used by the canonical fuzz recorder to decide
# which recorded traces to keep. `smallscope` keeps novel, short-shape
# traces; `lof` keeps outliers; `current` keeps everything with certs
# and distinct proposals. The value becomes the per-target artifact
# directory suffix: artifacts/traces/<target>_<strategy>/.
TRACE_SELECTION_STRATEGY ?= smallscope
export TRACE_SELECTION_STRATEGY

# Model-based fuzzing (mbf)
MUTATION_SEEDS_FOLDER ?= ../fuzz/artifacts/tlc_mutator
MUTATED_TRACES_DIR ?= ../fuzz/artifacts/mutated_traces
MUTATOR_ITERATIONS ?= 10000
MUTATOR_RESEED_FREQ ?= 100

include make/quint.mk
include make/tv.mk
include make/mbt.mk
include make/mbf.mk
include make/tlc.mk
