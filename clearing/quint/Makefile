.PHONY: check simulate test typecheck verify

QUINT ?= quint
JAVA_TOOL_OPTIONS ?= -Xmx28g

SOURCES := \
	types.qnt \
	transition.qnt \
	settlement.qnt \
	fixtures.qnt \
	instance.qnt \
	main.qnt \
	bounded.qnt \
	tests/scenarios.qnt

typecheck:
	@set -e; for source in $(SOURCES); do $(QUINT) typecheck $$source; done

test:
	$(QUINT) test tests/scenarios.qnt --verbosity=1

simulate:
	$(QUINT) run main.qnt \
		--backend=rust \
		--n-threads=4 \
		--max-samples=10000 \
		--max-steps=30 \
		--seed=0x5eedba11 \
		--invariant=all_invariants \
		--verbosity=1

check: typecheck test simulate

# This target requires a high-memory machine. It is intentionally separate
# from the ordinary CI checks.
verify:
	JAVA_TOOL_OPTIONS="$(JAVA_TOOL_OPTIONS)" $(QUINT) verify bounded.qnt \
		--invariant=lifecycle_invariants \
		--max-steps=3 \
		--verbosity=1
