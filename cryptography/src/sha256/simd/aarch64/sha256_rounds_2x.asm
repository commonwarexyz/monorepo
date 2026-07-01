// Inputs:
// v0-v1   first state
// v2-v3   second state
// v4-v7   first message schedule
// v8-v11  second message schedule
// k       SHA-256 round constants

.irp i,0,1,2,3
    ld1.4s {{v16}}, [{k}], #16
    add.4s v12, v4, v16
    add.4s v13, v8, v16
    mov.16b v14, v0
    mov.16b v15, v2
    sha256h.4s q0, q1, v12
    sha256h2.4s q1, q14, v12
    sha256h.4s q2, q3, v13
    sha256h2.4s q3, q15, v13

    sha256su0.4s v4, v5
    sha256su0.4s v8, v9
    sha256su1.4s v4, v6, v7
    sha256su1.4s v8, v10, v11

    ld1.4s {{v16}}, [{k}], #16
    add.4s v12, v5, v16
    add.4s v13, v9, v16
    mov.16b v14, v0
    mov.16b v15, v2
    sha256h.4s q0, q1, v12
    sha256h2.4s q1, q14, v12
    sha256h.4s q2, q3, v13
    sha256h2.4s q3, q15, v13

    sha256su0.4s v5, v6
    sha256su0.4s v9, v10
    sha256su1.4s v5, v7, v4
    sha256su1.4s v9, v11, v8

    ld1.4s {{v16}}, [{k}], #16
    add.4s v12, v6, v16
    add.4s v13, v10, v16
    mov.16b v14, v0
    mov.16b v15, v2
    sha256h.4s q0, q1, v12
    sha256h2.4s q1, q14, v12
    sha256h.4s q2, q3, v13
    sha256h2.4s q3, q15, v13

    sha256su0.4s v6, v7
    sha256su0.4s v10, v11
    sha256su1.4s v6, v4, v5
    sha256su1.4s v10, v8, v9

    ld1.4s {{v16}}, [{k}], #16
    add.4s v12, v7, v16
    add.4s v13, v11, v16
    mov.16b v14, v0
    mov.16b v15, v2
    sha256h.4s q0, q1, v12
    sha256h2.4s q1, q14, v12
    sha256h.4s q2, q3, v13
    sha256h2.4s q3, q15, v13

    .if \i != 3
        sha256su0.4s v7, v4
        sha256su0.4s v11, v8
        sha256su1.4s v7, v5, v6
        sha256su1.4s v11, v9, v10
    .endif
.endr
