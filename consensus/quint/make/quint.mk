# Quint spec targets: typecheck, test, run, verification scripts.

.PHONY: typecheck test longtest repl run

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
	cd tests && quint test --max-samples=1000 tests_n4f1b0_tla.qnt


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

check:
	./scripts/verify.sh check || true
	@echo
	./scripts/invariant.sh check

clean:
	./scripts/verify.sh clean
	./scripts/invariant.sh clean
