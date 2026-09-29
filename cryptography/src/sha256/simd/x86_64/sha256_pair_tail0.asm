            .macro FIXED_PAIR_ROUNDS4 offset
            movdqa xmm0, xmmword ptr [{fixed_wk} + \offset]
            sha256rnds2 xmm2, xmm1, xmm0
            sha256rnds2 xmm4, xmm3, xmm0
            vpshufd xmm0, xmm0, 14
            sha256rnds2 xmm1, xmm2, xmm0
            sha256rnds2 xmm3, xmm4, xmm0
            .endm

            FIXED_PAIR_ROUNDS4 0
            FIXED_PAIR_ROUNDS4 16
            FIXED_PAIR_ROUNDS4 32
            FIXED_PAIR_ROUNDS4 48
            FIXED_PAIR_ROUNDS4 64
            FIXED_PAIR_ROUNDS4 80
            FIXED_PAIR_ROUNDS4 96
            FIXED_PAIR_ROUNDS4 112
            FIXED_PAIR_ROUNDS4 128
            FIXED_PAIR_ROUNDS4 144
            FIXED_PAIR_ROUNDS4 160
            FIXED_PAIR_ROUNDS4 176
            FIXED_PAIR_ROUNDS4 192
            FIXED_PAIR_ROUNDS4 208
            FIXED_PAIR_ROUNDS4 224
            FIXED_PAIR_ROUNDS4 240

            paddd xmm1, xmm5
            paddd xmm2, xmm6
            paddd xmm3, xmm7
            paddd xmm4, xmm8

            STORE_DIGEST {left_output}, xmm1, xmm2, xmm5, xmm6, xmm7
            STORE_DIGEST {right_output}, xmm3, xmm4, xmm5, xmm6, xmm7

            .purgem FIXED_PAIR_ROUNDS4
            .purgem LOAD_STATE
            .purgem STORE_DIGEST
            .purgem ROUNDS4
            .purgem SCHEDULE
            .purgem PAIR_ROUNDS4
            .purgem ROUNDS_64
