            LOAD_STATE {state}, xmm14, xmm15, xmm5, xmm6
            movdqa xmm1, xmm14
            movdqa xmm2, xmm15
            movdqa xmm3, xmm14
            movdqa xmm4, xmm15

            movdqu xmm5, xmmword ptr [{left_a}]
            movdqu xmm6, xmmword ptr [{left_a} + 16]
            movdqu xmm7, xmmword ptr [{left_b}]
            movdqu xmm8, xmmword ptr [{left_b} + 16]
            movdqu xmm9, xmmword ptr [{right_a}]
            movdqu xmm10, xmmword ptr [{right_a} + 16]
            movdqu xmm11, xmmword ptr [{right_b}]
            movdqu xmm12, xmmword ptr [{right_b} + 16]

            pshufb xmm5, xmmword ptr [{mask}]
            pshufb xmm6, xmmword ptr [{mask}]
            pshufb xmm7, xmmword ptr [{mask}]
            pshufb xmm8, xmmword ptr [{mask}]
            pshufb xmm9, xmmword ptr [{mask}]
            pshufb xmm10, xmmword ptr [{mask}]
            pshufb xmm11, xmmword ptr [{mask}]
            pshufb xmm12, xmmword ptr [{mask}]
            ROUNDS_64

            paddd xmm1, xmm14
            paddd xmm2, xmm15
            paddd xmm3, xmm14
            paddd xmm4, xmm15

            movdqa xmm5, xmm1
            movdqa xmm6, xmm2
            movdqa xmm7, xmm3
            movdqa xmm8, xmm4
