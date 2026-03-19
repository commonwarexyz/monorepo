TRACES_ROOT ?= ../fuzz/artifacts/traces
TEST_DIR ?= traces

FUZZ_RUNS ?= 100

.PHONY: test typecheck repl check clean get_traces build_traces test_traces clean_traces tv

typecheck:
	quint typecheck types.qnt
	quint typecheck defs.qnt
	quint typecheck automaton.qnt
	quint typecheck replica.qnt
	quint typecheck option.qnt
	quint typecheck tests/tests_n4f1b0.qnt
	quint typecheck tests/tests_n4f1b1.qnt
	quint typecheck tests/tests_n5f1b1.qnt
	quint typecheck main_n4f1b0.qnt
	quint typecheck main_n4f1b1.qnt
	quint typecheck main_n5f1b1.qnt
	quint typecheck twins_n4f1b1.qnt

test:
	cd tests && quint test tests_n4f1b0.qnt
	cd tests && quint test tests_n4f1b1.qnt
	cd tests && quint test tests_n5f1b1.qnt

repl:
	echo "init\n step\n step\n step" | quint -r main_n4f1b0.qnt::main

MAX_STEPS ?= 100
MAX_SAMPLES ?= 1000
run:
	quint run --max-steps $(MAX_STEPS) --max-samples=$(MAX_SAMPLES) \
		--invariant=all_invariants main_n4f1b0.qnt
	quint run --max-steps $(MAX_STEPS) --max-samples=$(MAX_SAMPLES) \
		--invariant=all_invariants main_n4f1b1.qnt
	quint run --max-steps $(MAX_STEPS) --max-samples=$(MAX_SAMPLES) \
		--invariant=all_invariants main_n5f1b1.qnt
	quint run --max-steps $(MAX_STEPS) --max-samples=$(MAX_SAMPLES) \
    	--invariant=all_invariants twins_n4f1b1.qnt


get_traces:
	cargo +nightly fuzz run simplex_ed25519_quint_disrupter -- -runs=$(FUZZ_RUNS)

build_traces:
	@for dir in $(TRACES_ROOT)/*/; do \
		[ -d "$$dir" ] || continue; \
		echo "Converting traces from $$dir"; \
		cargo run -p commonware-consensus-fuzz --bin trace_to_quint -- "$$dir" $(TEST_DIR); \
	done

test_traces:
	./scripts/test_traces.sh

clean_traces:
	rm -rf $(TRACES_ROOT)
	rm -rf $(TEST_DIR)/trace_*.qnt

tv: clean_traces get_traces build_traces test_traces

clean:
	./scripts/verify.sh clean
	./scripts/invariant.sh clean

check:
	./scripts/verify.sh check || true
	@echo
	./scripts/invariant.sh check
