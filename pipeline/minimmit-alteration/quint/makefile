.PHONY: typecheck verify

typecheck:
	quint typecheck three_quorum_family.qnt
	quint typecheck main_n100f32_q2f.qnt
	quint typecheck main_n100f32_q2f1.qnt
	quint typecheck main_n100f19_q2f1.qnt

verify:
	quint verify --invariant=safe --max-steps=3 main_n100f32_q2f.qnt
	quint verify --invariant=expected --max-steps=3 main_n100f32_q2f.qnt
	quint verify --invariant=safe --max-steps=3 main_n100f32_q2f1.qnt
	quint verify --invariant=expected --max-steps=3 main_n100f32_q2f1.qnt
	quint verify --invariant=safe --max-steps=3 main_n100f19_q2f1.qnt
	quint verify --invariant=expected --max-steps=3 main_n100f19_q2f1.qnt
