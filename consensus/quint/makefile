# Simplex consensus specification: quint specs, trace validation,
# model-based testing, model-based fuzzing, tlc-controlled.
#
# Domain targets live in make/*.mk; this file holds shared variables.

# Trace validation (tv)
FUZZ_TRACES_ROOT ?= ../fuzz/artifacts/traces
FUZZ_CORPUS ?= ../fuzz/corpus
TRACES_DIR ?= traces
FUZZ_RUNS ?= -1

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
