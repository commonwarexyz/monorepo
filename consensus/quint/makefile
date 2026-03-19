TRACES_ROOT ?= ../fuzz/artifacts/traces
TEST_DIR ?= traces

FUZZ_RUNS ?= 1000

.PHONY: test typecheck repl check clean get_traces build_traces test_traces clean_traces tv generate_itf convert_itf replay_itf

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
	quint typecheck itf_n4f1b1.qnt

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

ITF_DIR ?= itf_traces
ITF_SAMPLES ?= 50
ITF_STEPS ?= 200

generate_itf:
	@mkdir -p $(ITF_DIR)
	@for i in $$(seq 1 $(ITF_SAMPLES)); do \
		quint run --main=itf_main --max-steps=$(ITF_STEPS) \
			--out-itf=$(ITF_DIR)/trace_$$i.itf.json \
			--invariant=all_invariants itf_n4f1b1.qnt || true; \
	done
	@echo "Generated ITF traces in $(ITF_DIR)/"

convert_itf:
	@mkdir -p $(ITF_DIR)/converted
	@for f in $(ITF_DIR)/*.itf.json; do \
		[ -f "$$f" ] || continue; \
		echo "Converting $$f"; \
		cargo run -p commonware-consensus-fuzz --bin itf_to_trace -- "$$f" $(ITF_DIR)/converted; \
	done
	@echo "Converted traces in $(ITF_DIR)/converted/"

replay_itf:
	@failed=0; total=0; \
	for f in $(ITF_DIR)/converted/*.json; do \
		[ -f "$$f" ] || continue; \
		case "$$f" in *_expected.json) continue;; esac; \
		expected="$${f%.json}_expected.json"; \
		total=$$((total + 1)); \
		echo "=== Replaying $$f ==="; \
		if cargo run -p commonware-consensus-fuzz --bin replay_trace -- "$$f" "$$expected"; then \
			echo "PASS"; \
		else \
			echo "FAIL"; \
			failed=$$((failed + 1)); \
		fi; \
		echo; \
	done; \
	echo "Results: $$((total - failed))/$$total passed"; \
	[ $$failed -eq 0 ]

clean:
	./scripts/verify.sh clean
	./scripts/invariant.sh clean

check:
	./scripts/verify.sh check || true
	@echo
	./scripts/invariant.sh check
