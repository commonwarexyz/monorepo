### Marshal (`consensus/src/marshal/`, `consensus/fuzz/marshal/`)

- No marshal base has a trusted continuation yet: the marshal drivers have no hook point, so
  synthesis refuses every marshal base at selection and never renders these rules. The
  follow-up that adds the marshal runner adapters writes them here: the bases, B and its
  actors at the release, the pins, the restart sites and the fault phases.
