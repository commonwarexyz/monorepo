// Inputs:
// v0-v7    states of messages 0-3 (abcd, efgh)
// v8-v23   message schedules of messages 0-3 (four vectors each)
// k        SHA-256 round constants

// Four rounds of one message with the round constants in v24, then expand
// its first schedule vector unless no rounds need it.
.macro SHA256_QUAD_STEP abcd, efgh, w0, w1, w2, w3, expand
    add.4s v25, v\w0, v24
    mov.16b v26, v\abcd
    sha256h.4s q\abcd, q\efgh, v25
    sha256h2.4s q\efgh, q26, v25
    .if \expand
        sha256su0.4s v\w0, v\w1
        sha256su1.4s v\w0, v\w2, v\w3
    .endif
.endm

.irp i,0,1,2,3
    ld1.4s {{v24}}, [{k}], #16
    SHA256_QUAD_STEP 0, 1, 8, 9, 10, 11, (\i != 3)
    SHA256_QUAD_STEP 2, 3, 12, 13, 14, 15, (\i != 3)
    SHA256_QUAD_STEP 4, 5, 16, 17, 18, 19, (\i != 3)
    SHA256_QUAD_STEP 6, 7, 20, 21, 22, 23, (\i != 3)

    ld1.4s {{v24}}, [{k}], #16
    SHA256_QUAD_STEP 0, 1, 9, 10, 11, 8, (\i != 3)
    SHA256_QUAD_STEP 2, 3, 13, 14, 15, 12, (\i != 3)
    SHA256_QUAD_STEP 4, 5, 17, 18, 19, 16, (\i != 3)
    SHA256_QUAD_STEP 6, 7, 21, 22, 23, 20, (\i != 3)

    ld1.4s {{v24}}, [{k}], #16
    SHA256_QUAD_STEP 0, 1, 10, 11, 8, 9, (\i != 3)
    SHA256_QUAD_STEP 2, 3, 14, 15, 12, 13, (\i != 3)
    SHA256_QUAD_STEP 4, 5, 18, 19, 16, 17, (\i != 3)
    SHA256_QUAD_STEP 6, 7, 22, 23, 20, 21, (\i != 3)

    ld1.4s {{v24}}, [{k}], #16
    SHA256_QUAD_STEP 0, 1, 11, 8, 9, 10, (\i != 3)
    SHA256_QUAD_STEP 2, 3, 15, 12, 13, 14, (\i != 3)
    SHA256_QUAD_STEP 4, 5, 19, 16, 17, 18, (\i != 3)
    SHA256_QUAD_STEP 6, 7, 23, 20, 21, 22, (\i != 3)
.endr

.purgem SHA256_QUAD_STEP
