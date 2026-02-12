.PHONY: test typecheck run run-adversarial clean all

typecheck:
	quint typecheck types.qnt
	quint typecheck defs.qnt
	quint typecheck dkg.qnt
	quint typecheck main_n4f1b0.qnt
	quint typecheck main_n4f1b1.qnt
	quint typecheck main_n7f2b0.qnt
	quint typecheck main_n7f2b2.qnt
	quint typecheck tests/scenarios.qnt
	quint typecheck tests/scenarios_n7.qnt
	quint typecheck tests/test_adversarial.qnt

test:
	quint test tests/scenarios.qnt
	quint test tests/scenarios_n7.qnt

run:
	quint run --max-steps=40 --max-samples=1000 \
		--invariant=safe main_n4f1b0.qnt
	quint run --max-steps=40 --max-samples=1000 \
		--invariant=safe main_n4f1b1.qnt

# Run n=7 configurations (fewer samples due to larger state space)
run-n7:
	quint run --max-steps=30 --max-samples=500 \
		--invariant=safe main_n7f2b0.qnt
	quint run --max-steps=30 --max-samples=500 \
		--invariant=safe main_n7f2b2.qnt

# Run adversarial test to demonstrate share_secrecy violation
run-adversarial:
	quint run tests/test_adversarial.qnt \
		--step=step_with_adversarial \
		--invariant=share_secrecy_violated_example \
		--max-samples=100 --max-steps=10

clean:
	rm -f *.itf.json

all: typecheck test run
