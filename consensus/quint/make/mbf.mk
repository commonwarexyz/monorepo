# Model-based fuzzing (mbf): get traces from the real implementation, mutate traces, get feedback via tlc-controlled,
# replay accepted mutations on the implementation.
#
#   make mbf_live          # run both in parallel (fuzz + watch)
#   make mbf_live_fuzz     # mutator + tlc-controlled only
#   make mbf_live_watch    # replay watcher only
#   mbf_live_trace_gen     # run a libfuzzer target and get interesting traces from it

MBF_FAULTS ?= 0 # number of faulty nodes

MBF_TRACE_GEN_TARGET ?= simplex_ed25519_quint_honest
MBF_TRACE_GEN_FUZZ_RUNS ?= -1
MBF_TRACE_GEN_SRC ?= $(FUZZ_TRACES_ROOT)/$(MBF_TRACE_GEN_TARGET)_$(TRACE_SELECTION_STRATEGY)
MBF_TRACE_STATIC_MAX_VIEWS ?= 6
MBF_TRACE_STATIC_MAX_CONTAINERS ?= 4

.PHONY: mutate_traces replay_mutated_traces clean_mutated_traces mbf_live_fuzz mbf_live_watch mbf_live mbf_live_trace_fuzz_gen mbf_live_trace_static_gen

mutate_traces:
	MUTATOR_ITERATIONS=$(MUTATOR_ITERATIONS) \
	MUTATOR_RESEED_FREQ=$(MUTATOR_RESEED_FREQ) \
	MUTATION_SEEDS_FOLDER=$(MUTATION_SEEDS_FOLDER) \
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
		if REPLAY_FAULTS=$(MBF_FAULTS) cargo run -p commonware-consensus-fuzz --bin replay_trace -- "$$f"; then \
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
		port=$$(./scripts/free_port.sh); \
		echo "using port $$port"; \
		TLC_PORT=$$port ./scripts/tlc.sh run & \
		tlc_pid=$$!; \
		cleanup() { \
			kill $$tlc_pid 2>/dev/null || true; \
			wait $$tlc_pid 2>/dev/null || true; \
		}; \
		trap cleanup EXIT INT TERM; \
		url="http://localhost:$$port/health"; \
		deadline=$$((SECONDS + 40)); \
		while ! curl -fsS --max-time 2 "$$url" >/dev/null 2>&1; do \
			if [ $$SECONDS -ge $$deadline ]; then \
				echo "tlc-controlled did not start within 40s"; \
				exit 1; \
			fi; \
			sleep 1; \
		done; \
		echo "tlc-controlled ready on port $$port"; \
		TLC_URL="http://localhost:$$port/execute" \
		MUTATOR_ITERATIONS=$(MUTATOR_ITERATIONS) \
		MUTATOR_SEED=$(MUTATOR_SEED) \
		MUTATOR_MUT_PER_TRACE=$(MUTATOR_MUT_PER_TRACE) \
		MUTATOR_RESEED_FREQ=$(MUTATOR_RESEED_FREQ) \
		MUTATION_SEEDS_FOLDER=$(MUTATION_SEEDS_FOLDER) \
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
				if REPLAY_FAULTS=$(MBF_FAULTS) cargo run -p commonware-consensus-fuzz --bin replay_trace -- "$$f"; then \
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

mbf_live_trace_fuzz_gen:
	@bash -eu -o pipefail -c '\
		src="$(MBF_TRACE_GEN_SRC)"; \
		dst="$(MUTATION_SEEDS_FOLDER)"; \
		mkdir -p "$$dst"; \
		TRACE_SELECTION_STRATEGY="$(TRACE_SELECTION_STRATEGY)" \
		MIN_REQUIRED_CONTAINERS="$(MIN_REQUIRED_CONTAINERS)" \
		MAX_REQUIRED_CONTAINERS="$(MAX_REQUIRED_CONTAINERS)" \
		cargo +nightly fuzz run "$(MBF_TRACE_GEN_TARGET)" -- -runs=$(MBF_TRACE_GEN_FUZZ_RUNS) & \
		fuzz=$$!; \
		cleanup() { \
			kill $$fuzz 2>/dev/null || true; \
			wait $$fuzz 2>/dev/null || true; \
		}; \
		trap cleanup EXIT INT TERM; \
		seen_dir="$$dst/.seen"; \
		mkdir -p "$$seen_dir"; \
		echo "generating traces into $$src, copying to $$dst..."; \
		while kill -0 $$fuzz 2>/dev/null; do \
			if [ -d "$$src" ]; then \
				for f in "$$src"/*.json; do \
					[ -f "$$f" ] || continue; \
					name=$$(basename "$$f"); \
					[ -f "$$seen_dir/$$name" ] && continue; \
					cp "$$f" "$$dst/$$name"; \
					: > "$$seen_dir/$$name"; \
					echo "copied $$name -> $$dst"; \
				done; \
			fi; \
			sleep 2; \
		done; \
		wait $$fuzz; \
	'

mbf_live_trace_static_gen:
	@bash -eu -o pipefail -c '\
		dst="$(MUTATION_SEEDS_FOLDER)"; \
		mkdir -p "$$dst"; \
		cargo run -p commonware-consensus-fuzz --bin generate_small_honest_traces -- \
			"$$dst" \
			--max-views "$(MBF_TRACE_STATIC_MAX_VIEWS)" \
			--max-containers "$(MBF_TRACE_STATIC_MAX_CONTAINERS)"; \
	'
	
