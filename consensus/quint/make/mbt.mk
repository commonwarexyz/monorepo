# Model-based testing: ITF generation, conversion, replay, conformance, IST.

ITF_DIR ?= itf_traces
ITF_SAMPLES ?= 50
ITF_STEPS ?= 200
IST_STEPS ?= 200
IST_URL ?= http://localhost:8822/rpc

.PHONY: generate_itf convert_itf replay_itf generate_mbt_unit_test_traces clean_mbt_traces mbt_unit_tests mbt_replay generate_itf_test conformance_roundtrip ist

generate_itf:
	@mkdir -p $(ITF_DIR)
	@for i in $$(seq 1 $(ITF_SAMPLES)); do \
		quint run --main=itf_main --max-steps=$(ITF_STEPS) \
			--out-itf=$(ITF_DIR)/trace_$$i.itf.json \
			--invariant=safe_invariants itf_n4f1b1.qnt || true; \
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

generate_mbt_unit_test_traces:
	@mkdir -p $(ITF_DIR)
	quint test --out-itf=$(ITF_DIR)/trace_test_n4f1b0_happyPathFinalizeTest.itf.json --match=happyPathFinalizeTest  ./tests/tests_n4f1b0.qnt
	quint test --out-itf=$(ITF_DIR)/trace_test_n4f1b0_allCorrectReplicasFinalizeTwoBlocksTest.itf.json --match=allCorrectReplicasFinalizeTwoBlocksTest  ./tests/tests_n4f1b0.qnt
	quint test --out-itf=$(ITF_DIR)/trace_test_n4f1b0_timeoutViewsThenFinalizeTest.itf.json --match=timeoutViewsThenFinalizeTest  ./tests/tests_n4f1b0.qnt
	quint test --out-itf=$(ITF_DIR)/trace_test_n4f1b0_wrongParentNullifyThenCorrectFinalizeTest.itf.json --match=wrongParentNullifyThenCorrectFinalizeTest  ./tests/tests_n4f1b0.qnt
	quint test --out-itf=$(ITF_DIR)/trace_test_n4f1b0_slowReplicaAlwaysNullifiesTest.itf.json --match=slowReplicaAlwaysNullifiesTest  ./tests/tests_n4f1b0.qnt

clean_mbt_traces:
	rm -rf $(ITF_DIR)/

mbt_unit_tests: clean_mbt_traces generate_mbt_unit_test_traces convert_itf replay_itf
mbt_replay: convert_itf replay_itf

generate_itf_test:
	@mkdir -p $(ITF_DIR)
	@for dir in $(FUZZ_TRACES_ROOT)/*/; do \
		quint test --main=itf_main --max-steps=$(ITF_STEPS) \
			--out-itf=$(ITF_DIR)/trace_$$i.itf.json \
			--invariant=safe_invariants itf_n4f1b1.qnt || true; \
	done
	@echo "Generated ITF traces in $(ITF_DIR)/"

conformance_roundtrip: clean_mbt_traces clean_fuzz_traces clean_traces
	$(MAKE) FUZZ_RUNS=10000 get_fuzz_traces
	$(MAKE) build_quint_tests_from_fuzz_traces
	OUT_ITF_DIR=$(ITF_DIR) ./scripts/test_traces.sh
	$(MAKE) convert_itf
	$(MAKE) replay_itf

ist:
	@echo "Starting IST (ensure Apalache is running on port 8822)"
	@echo "  docker run --rm -p 8822:8822 ghcr.io/apalache-mc/apalache:latest server --server-type=explorer"
	cargo run -p commonware-consensus-fuzz --bin ist -- \
		--spec itf_n4f1b1.qnt --steps $(IST_STEPS) --url $(IST_URL)
