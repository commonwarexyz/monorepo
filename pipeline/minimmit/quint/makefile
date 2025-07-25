.PHONY: test typecheck repl check clean

typecheck:
	quint typecheck types.qnt
	quint typecheck main_n6f1b0.qnt
	quint typecheck replica.qnt

test:
	cd tests && quint test tests_n6f1b0.qnt
	cd tests && quint test tests_n6f1b1.qnt

repl:
	echo "init\n step\n step\n step" | quint -r main_n6f1b0.qnt::main 

run:
	quint run --max-steps 20 --max-samples=100 \
		--invariant=all_invariants main_n6f1b0.qnt 

verify:
	quint verify --random-transitions=true --max-steps 20 \
		--invariant=all_invariants main_n6f1b1.qnt

clean:
	./scripts/verify.sh clean

check:
	./scripts/verify.sh check
