.PHONY: test typecheck repl check clean

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
	quint typecheck main_n6f2b2.qnt
	quint typecheck main_n7f1b1.qnt

test:
	cd tests && quint test tests_n6f1b0.qnt
	cd tests && quint test tests_n6f1b1.qnt
	cd tests && quint test tests_n7f1b1.qnt

repl:
	echo "init\n step\n step\n step" | quint -r main_n6f0.qnt::main

run:
	quint run --max-steps 20 --max-samples=100 \
		--invariant=all_invariants main_n6f1b0.qnt
	quint run --max-steps 20 --max-samples=100 \
		--invariant=all_invariants main_n6f1b1.qnt	
	quint run --max-steps 20 --max-samples=100 \
		--invariant=all_invariants main_n7f1b1.qnt		

clean:
	./scripts/verify.sh clean
	./scripts/invariant.sh clean

check:
	./scripts/verify.sh check || true
	@echo
	./scripts/invariant.sh check
