            .macro FIXED_ROUNDS4 offset
            movdqa xmm0, xmmword ptr [{fixed_wk} + \offset]
            sha256rnds2 xmm2, xmm1, xmm0
            pshufd xmm0, xmm0, 14
            sha256rnds2 xmm1, xmm2, xmm0
            .endm

            LOAD_STATE {state}, xmm14, xmm15, xmm5, xmm6
            movdqa xmm1, xmm14
            movdqa xmm2, xmm15

            movdqu xmm5, xmmword ptr [{left}]
            movdqu xmm6, xmmword ptr [{left} + 16]
            movdqu xmm7, xmmword ptr [{right}]
            movdqu xmm8, xmmword ptr [{right} + 16]

            pshufb xmm5, xmmword ptr [{mask}]
            pshufb xmm6, xmmword ptr [{mask}]
            pshufb xmm7, xmmword ptr [{mask}]
            pshufb xmm8, xmmword ptr [{mask}]
            SINGLE_ROUNDS_64

            paddd xmm1, xmm14
            paddd xmm2, xmm15
            movdqa xmm14, xmm1
            movdqa xmm15, xmm2

            FIXED_ROUNDS4 0
            FIXED_ROUNDS4 16
            FIXED_ROUNDS4 32
            FIXED_ROUNDS4 48
            FIXED_ROUNDS4 64
            FIXED_ROUNDS4 80
            FIXED_ROUNDS4 96
            FIXED_ROUNDS4 112
            FIXED_ROUNDS4 128
            FIXED_ROUNDS4 144
            FIXED_ROUNDS4 160
            FIXED_ROUNDS4 176
            FIXED_ROUNDS4 192
            FIXED_ROUNDS4 208
            FIXED_ROUNDS4 224
            FIXED_ROUNDS4 240

            paddd xmm1, xmm14
            paddd xmm2, xmm15

            .purgem FIXED_ROUNDS4
