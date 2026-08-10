.PHONY: typecheck test repl run clean check

typecheck:
	quint typecheck types.qnt
	quint typecheck defs.qnt
	quint typecheck replica.qnt
	quint typecheck option.qnt
	quint typecheck tests/tests_n6f1b0.qnt
	quint typecheck tests/tests_n6f1b1.qnt
	quint typecheck tests/tests_n7f1b1.qnt
	quint typecheck main_n6f1b0.qnt
	quint typecheck main_n6f1b1.qnt
	quint typecheck main_n6f1b2.qnt
	quint typecheck main_twins_n6f1b1.qnt

test:
	cd tests && quint test --backend typescript tests_n6f1b0.qnt
	cd tests && quint test --backend typescript tests_n6f1b1.qnt
	cd tests && quint test --backend typescript tests_n7f1b1.qnt

repl:
	echo "init\n step\n step\n step" | quint -r main_n6f1b0.qnt::main

MAX_STEPS ?= 200
MAX_SAMPLES ?= 1000
run:
	quint run --max-steps $(MAX_STEPS) --max-samples=$(MAX_SAMPLES) \
		--invariant=all_invariants main_n6f1b0.qnt
	quint run --max-steps $(MAX_STEPS) --max-samples=$(MAX_SAMPLES) \
		--invariant=all_invariants main_n6f1b1.qnt	
	quint run --max-steps $(MAX_STEPS) --max-samples=$(MAX_SAMPLES) \
		--invariant=all_invariants main_twins_n6f1b1.qnt

clean:
	./scripts/verify.sh clean
	./scripts/invariant.sh clean

check:
	./scripts/verify.sh check || true
	@echo
	./scripts/invariant.sh check
