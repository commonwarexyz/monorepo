# Model-based fuzzing (mbf): mutate traces, validate via tlc-controlled,
# replay accepted mutations on the real implementation.
#
#   make mbf_live          # run both in parallel (fuzz + watch)
#   make mbf_live_fuzz     # mutator + tlc-controlled only
#   make mbf_live_watch    # replay watcher only

MBF_TLC_PORT ?= 2023
MBF_FAULTS ?= 0

.PHONY: mutate_traces replay_mutated_traces clean_mutated_traces mbf_live_fuzz mbf_live_watch mbf_live

mutate_traces:
	MUTATOR_ITERATIONS=$(MUTATOR_ITERATIONS) \
	MUTATOR_SEED=$(MUTATOR_SEED) \
	MUTATOR_MUT_PER_TRACE=$(MUTATOR_MUT_PER_TRACE) \
	MUTATOR_RESEED_FREQ=$(MUTATOR_RESEED_FREQ) \
	MUTATED_TRACES_SEED_DIR=$(MUTATED_TRACES_SEED_DIR) \
	MUTATOR_FAULTS=$(MBF_FAULTS) \
	MUTATOR_DEBUG=true \
	cargo run -p commonware-consensus-fuzz --bin trace_mutator

replay_mutated_traces:
	@if [ ! -d "$(MUTATED_TRACES_DIR)" ]; then \
		echo "No mutated traces directory: $(MUTATED_TRACES_DIR)"; \
		exit 1; \
	fi; \
	failed=0; total=0; \
	for f in $(MUTATED_TRACES_DIR)/*.json; do \
		[ -f "$$f" ] || continue; \
		total=$$((total + 1)); \
		echo "=== Replaying $$f ==="; \
		if cargo run -p commonware-consensus-fuzz --bin replay_trace -- "$$f"; then \
			echo "PASS"; \
		else \
			echo "FAIL"; \
			failed=$$((failed + 1)); \
		fi; \
		echo; \
	done; \
	echo "Results: $$((total - failed))/$$total passed"; \
	[ $$failed -eq 0 ]

clean_mutated_traces:
	rm -rf $(MUTATED_TRACES_DIR)

mbf_live_fuzz:
	@bash -eu -o pipefail -c '\
		$(MAKE) -s tlc_compile; \
		./scripts/tlc.sh run & \
		tlc_pid=$$!; \
		cleanup() { \
			kill $$tlc_pid 2>/dev/null || true; \
			wait $$tlc_pid 2>/dev/null || true; \
		}; \
		trap cleanup EXIT INT TERM; \
		url="http://localhost:$(MBF_TLC_PORT)/health"; \
		deadline=$$((SECONDS + 60)); \
		while ! curl -fsS --max-time 2 "$$url" >/dev/null 2>&1; do \
			if [ $$SECONDS -ge $$deadline ]; then \
				echo "tlc-controlled did not start within 60s"; \
				exit 1; \
			fi; \
			sleep 1; \
		done; \
		echo "tlc-controlled ready on port $(MBF_TLC_PORT)"; \
		TLC_URL="http://localhost:$(MBF_TLC_PORT)/execute" \
		MUTATOR_ITERATIONS=$(MUTATOR_ITERATIONS) \
		MUTATOR_SEED=$(MUTATOR_SEED) \
		MUTATOR_MUT_PER_TRACE=$(MUTATOR_MUT_PER_TRACE) \
		MUTATOR_RESEED_FREQ=$(MUTATOR_RESEED_FREQ) \
		MUTATED_TRACES_SEED_DIR=$(MUTATED_TRACES_SEED_DIR) \
		MUTATOR_FAULTS=$(MBF_FAULTS) \
		cargo run -p commonware-consensus-fuzz --bin trace_mutator; \
	'

mbf_live_watch:
	@bash -eu -o pipefail -c '\
		dir="$(MUTATED_TRACES_DIR)"; \
		seen_dir="$$dir/.seen"; \
		mkdir -p "$$dir" "$$seen_dir"; \
		echo "watching $$dir for new traces..."; \
		while true; do \
			for f in "$$dir"/*.json; do \
				[ -f "$$f" ] || continue; \
				hash=$$(basename "$$f" .json); \
				[ -f "$$seen_dir/$$hash" ] && continue; \
				echo "=== Replaying $$f ==="; \
				if cargo run -p commonware-consensus-fuzz --bin replay_trace -- "$$f"; then \
					echo "PASS"; \
				else \
					echo "FAIL"; \
				fi; \
				: > "$$seen_dir/$$hash"; \
			done; \
			sleep 2; \
		done; \
	'

mbf_live: clean_mutated_traces
	@bash -eu -o pipefail -c '\
		$(MAKE) mbf_live_watch & \
		watcher=$$!; \
		cleanup() { \
			kill $$watcher 2>/dev/null || true; \
			wait $$watcher 2>/dev/null || true; \
		}; \
		trap cleanup EXIT INT TERM; \
		$(MAKE) mbf_live_fuzz; \
		echo "fuzzer finished, draining watcher..."; \
		sleep 5; \
		kill $$watcher 2>/dev/null || true; \
		wait $$watcher 2>/dev/null || true; \
	'
