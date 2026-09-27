// Inputs:
// v0-v1   first state
// v2-v3   second state
// k       schedule words plus round constants of a block both messages share

.rept 16
    ld1.4s {{v16}}, [{k}], #16
    mov.16b v14, v0
    mov.16b v15, v2
    sha256h.4s q0, q1, v16
    sha256h2.4s q1, q14, v16
    sha256h.4s q2, q3, v16
    sha256h2.4s q3, q15, v16
.endr
