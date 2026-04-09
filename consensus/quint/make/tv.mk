# Trace validation: fuzz -> quint trace -> quint test pipeline.

.PHONY: get_fuzz_traces build_quint_tests_from_fuzz_traces test_traces clean_fuzz_traces clean_traces tv tv_live tv_live_fuzz tv_live_watch test_encoder

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
