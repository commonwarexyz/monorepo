# Simplex consensus specification: quint specs, trace validation,
# model-based testing, model-based fuzzing, tlc-controlled.
#
# Domain targets live in make/*.mk; this file holds shared variables.

# Trace validation (tv)
FUZZ_TRACES_ROOT ?= ../fuzz/artifacts/traces
FUZZ_CORPUS ?= ../fuzz/corpus
TRACES_DIR ?= traces
TRACE_TARGET ?= simplex_ed25519_quint_byzantine
TRACE_TARGETS ?= [simplex_ed25519_quint_honest,simplex_ed25519_quint_disrupter, simplex_ed25519_quint_byzantine, simplex_ed25519_quint_twins]
FUZZ_RUNS ?= -1
TRACE_SELECTION_STRATEGY ?= smallscope
MIN_REQUIRED_CONTAINERS ?= 3
MAX_REQUIRED_CONTAINERS ?= 10

# Model-based fuzzing (mbf)
MUTATION_SEEDS_FOLDER ?= ../fuzz/corpus/tlc_mutator
MUTATED_TRACES_DIR ?= ../fuzz/artifacts/mutated_traces
MUTATED_TRACES_SEED_DIR ?=
MUTATOR_ITERATIONS ?= 1000
MUTATOR_SEED ?= 0
MUTATOR_MUT_PER_TRACE ?= 2
MUTATOR_RESEED_FREQ ?= 100

include make/quint.mk
include make/tv.mk
include make/mbt.mk
include make/mbf.mk
include make/tlc.mk
