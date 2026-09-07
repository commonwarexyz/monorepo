.PHONY: test typecheck repl run check clean

typecheck:
	quint typecheck option.qnt
	quint typecheck types.qnt
	quint typecheck blocks.qnt
	quint typecheck defs.qnt
	quint typecheck chainrules.qnt
	quint typecheck sweep.qnt
	quint typecheck da.qnt
	quint typecheck consensus.qnt
	quint typecheck tests/tests_extraction.qnt
	quint typecheck tests/tests_n6t1f1.qnt
	quint typecheck tests/tests_byzantine_n6t1f1.qnt
	quint typecheck main_da_n6t1f1.qnt
	quint typecheck main_n6t1f1.qnt
	quint typecheck main_n7t1f1.qnt

test:
	quint test tests/tests_extraction.qnt
	quint test tests/tests_n6t1f1.qnt
	quint test tests/tests_byzantine_n6t1f1.qnt

repl:
	quint -r main_n6t1f1.qnt::main_n6t1f1

run:
	quint run --max-steps 20 --max-samples=100 \
		--invariant=da_invariants main_da_n6t1f1.qnt
	quint run --max-steps 20 --max-samples=100 \
		--invariant=all_invariants main_n6t1f1.qnt
	quint run --max-steps 20 --max-samples=100 \
		--invariant=all_invariants main_n7t1f1.qnt

clean:
	./scripts/verify.sh clean
	./scripts/invariant.sh clean

check:
	./scripts/verify.sh check || true
	@echo
	./scripts/invariant.sh check
