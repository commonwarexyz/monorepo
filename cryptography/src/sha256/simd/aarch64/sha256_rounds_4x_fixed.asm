// Inputs:
// v0-v7    states of messages 0-3 (abcd, efgh)
// padding  schedule words plus round constants of a block all four messages
//          share

.rept 16
    ld1.4s {{v24}}, [{padding}], #16
    mov.16b v26, v0
    sha256h.4s q0, q1, v24
    sha256h2.4s q1, q26, v24
    mov.16b v26, v2
    sha256h.4s q2, q3, v24
    sha256h2.4s q3, q26, v24
    mov.16b v26, v4
    sha256h.4s q4, q5, v24
    sha256h2.4s q5, q26, v24
    mov.16b v26, v6
    sha256h.4s q6, q7, v24
    sha256h2.4s q7, q26, v24
.endr
