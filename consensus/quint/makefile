FUZZ_TRACES_ROOT ?= ../fuzz/artifacts/traces
FUZZ_CORPUS ?= ../fuzz/corpus
TRACES_DIR ?= traces
TRACE_TARGETS ?= [simplex_ed25519_quint_honest,simplex_ed25519_quint_disrupter, simplex_ed25519_quint_byzantine, simplex_ed25519_quint_twins]
FUZZ_RUNS ?= -1
TRACE_SELECTION_STRATEGY ?= smallscope
MIN_REQUIRED_CONTAINERS ?= 3
MAX_REQUIRED_CONTAINERS ?= 10

.PHONY: test typecheck repl check clean get_fuzz_traces build_quint_tests_from_fuzz_traces test_traces clean_fuzz_traces tv tv_live tv_live_fuzz tv_live_watch generate_itf convert_itf replay_itf clean_mbt_traces conformance_roundtrip ist

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
	cd tests && quint test --max-samples=1000 tests_n4f1b0.qnt
	cd tests && quint test --max-samples=1000 tests_n4f1b1.qnt
	cd tests && quint test --max-samples=1000 tests_n5f1b1.qnt

longtest:
	cd tests && quint test --max-samples=100000 --backend=rust tests_n4f1b0.qnt
	cd tests && quint test --max-samples=100000 --backend=rust tests_n4f1b1.qnt
	cd tests && quint test --max-samples=100000 --backend=rust tests_n5f1b1.qnt
	quint run --max-steps=1000 --max-samples=1000 --invariant=safe_invariants --backend=rust main_n4f1b0.qnt
	quint run --max-steps=1000 --max-samples=1000 --invariant=safe_invariants --backend=rust main_n4f1b1.qnt

repl:
	echo "init\n step\n step\n step" | quint -r main_n4f1b0.qnt::main

MAX_STEPS ?= 400
MAX_SAMPLES ?= 10000
run:
	quint run --max-steps $(MAX_STEPS) --max-samples=$(MAX_SAMPLES) --backend=rust \
		--invariant=safe_invariants main_n4f1b0.qnt
	quint run --max-steps $(MAX_STEPS) --max-samples=$(MAX_SAMPLES) --backend=rust \
		--invariant=safe_invariants main_n4f1b1.qnt
	quint run --max-steps $(MAX_STEPS) --max-samples=$(MAX_SAMPLES) --backend=rust \
		--invariant=safe_invariants main_n5f1b1.qnt

get_fuzz_traces:
	TRACE_SELECTION_STRATEGY=$(TRACE_SELECTION_STRATEGY) \
	MIN_REQUIRED_CONTAINERS=$(MIN_REQUIRED_CONTAINERS) \
	MAX_REQUIRED_CONTAINERS=$(MAX_REQUIRED_CONTAINERS) \
	cargo +nightly fuzz run $(TRACE_TARGET) -- -runs=$(FUZZ_RUNS)

build_quint_tests_from_fuzz_traces:
	@for dir in $(FUZZ_TRACES_ROOT)/*/; do \
		[ -d "$$dir" ] || continue; \
		echo "Converting traces from $$dir"; \
		cargo run -p commonware-consensus-fuzz --bin trace_to_quint -- "$$dir" $(TRACES_DIR); \
	done

test_traces:
	TRACE_SELECTION_STRATEGY=$(TRACE_SELECTION_STRATEGY) \
	./scripts/test_traces.sh

clean_fuzz_traces:
	rm -rf $(FUZZ_TRACES_ROOT)
	rm -rf $(FUZZ_CORPUS)

clean_traces:
	rm -rf $(TRACES_DIR)

tv: clean_fuzz_traces clean_traces get_fuzz_traces build_quint_tests_from_fuzz_traces test_traces

tv_live: clean_fuzz_traces clean_traces
	@bash -eu -o pipefail -c '\
		TRACE_SELECTION_STRATEGY="$(TRACE_SELECTION_STRATEGY)" \
		./scripts/watch_new_traces.sh "$(TRACES_DIR)" "$(FUZZ_TRACES_ROOT)" & \
		watcher=$$!; \
		cleanup() { \
			kill $$watcher 2>/dev/null || true; \
			wait $$watcher 2>/dev/null || true; \
		}; \
		trap cleanup EXIT INT TERM; \
		TRACE_SELECTION_STRATEGY="$(TRACE_SELECTION_STRATEGY)" \
		MIN_REQUIRED_CONTAINERS="$(MIN_REQUIRED_CONTAINERS)" \
		MAX_REQUIRED_CONTAINERS="$(MAX_REQUIRED_CONTAINERS)" \
		cargo +nightly fuzz run "$(TRACE_TARGET)" -- -runs=$(FUZZ_RUNS) & \
		fuzz=$$!; \
		while kill -0 $$watcher 2>/dev/null && kill -0 $$fuzz 2>/dev/null; do \
			sleep 1; \
		done; \
		if ! kill -0 $$watcher 2>/dev/null; then \
			status=0; \
			wait $$watcher || status=$$?; \
			kill $$fuzz 2>/dev/null || true; \
			wait $$fuzz 2>/dev/null || true; \
			exit $$status; \
		fi; \
		status=0; \
		wait $$fuzz || status=$$?; \
		exit $$status; \
	'

tv_live_fuzz:
	rm -rf $(FUZZ_TRACES_ROOT)
	@bash -eu -c '\
		set -m; \
		raw="$(TRACE_TARGETS)"; \
		raw="$${raw#[}"; raw="$${raw%]}"; \
		IFS=", " read -ra targets <<< "$$raw"; \
		pids=(); \
		cleanup() { \
			for pid in "$${pids[@]}"; do \
				kill -- -$$pid 2>/dev/null || true; \
			done; \
			for pid in "$${pids[@]}"; do \
				wait $$pid 2>/dev/null || true; \
			done; \
		}; \
		trap cleanup EXIT INT TERM; \
		for target in "$${targets[@]}"; do \
			TRACE_SELECTION_STRATEGY="$(TRACE_SELECTION_STRATEGY)" \
			MIN_REQUIRED_CONTAINERS="$(MIN_REQUIRED_CONTAINERS)" \
			MAX_REQUIRED_CONTAINERS="$(MAX_REQUIRED_CONTAINERS)" \
			cargo +nightly fuzz run "$$target" -- -runs=$(FUZZ_RUNS) & \
			pids+=($$!); \
		done; \
		status=0; \
		for pid in "$${pids[@]}"; do \
			wait $$pid || status=$$?; \
		done; \
		exit $$status; \
	'

tv_live_watch: clean_traces
	TRACE_SELECTION_STRATEGY=$(TRACE_SELECTION_STRATEGY) \
	./scripts/watch_new_traces.sh "$(TEST_DIR)" "$(FUZZ_TRACES_ROOT)"

test_encoder:
	cargo test -p commonware-consensus-fuzz -- test_encoder_roundtrip
ITF_DIR ?= itf_traces
ITF_SAMPLES ?= 50
ITF_STEPS ?= 200

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
	$(MAKE) FUZZ_RUNS=100 get_fuzz_traces
	$(MAKE) build_quint_tests_from_fuzz_traces
	OUT_ITF_DIR=$(ITF_DIR) ./scripts/test_traces.sh
	$(MAKE) convert_itf
	$(MAKE) replay_itf

IST_STEPS ?= 200
IST_URL ?= http://localhost:8822/rpc

ist:
	@echo "Starting IST (ensure Apalache is running on port 8822)"
	@echo "  docker run --rm -p 8822:8822 ghcr.io/apalache-mc/apalache:latest server --server-type=explorer"
	cargo run -p commonware-consensus-fuzz --bin ist -- \
		--spec itf_n4f1b1.qnt --steps $(IST_STEPS) --url $(IST_URL)

clean:
	./scripts/verify.sh clean
	./scripts/invariant.sh clean

check:
	./scripts/verify.sh check || true
	@echo
	./scripts/invariant.sh check
