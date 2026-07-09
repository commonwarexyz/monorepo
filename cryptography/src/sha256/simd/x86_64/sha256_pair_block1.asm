            LOAD_STATE {state}, xmm14, xmm15, xmm5, xmm6
            movdqa xmm1, xmm14
            movdqa xmm2, xmm15
            movdqa xmm3, xmm14
            movdqa xmm4, xmm15

            movdqu xmm5, xmmword ptr [{left}]
            movdqu xmm6, xmmword ptr [{left} + 16]
            movdqu xmm7, xmmword ptr [{left} + 32]
            movdqu xmm8, xmmword ptr [{left} + 48]
            movdqu xmm9, xmmword ptr [{right}]
            movdqu xmm10, xmmword ptr [{right} + 16]
            movdqu xmm11, xmmword ptr [{right} + 32]
            movdqu xmm12, xmmword ptr [{right} + 48]

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

            sub rsp, 64
            movdqu xmmword ptr [rsp], xmm1
            movdqu xmmword ptr [rsp + 16], xmm2
            movdqu xmmword ptr [rsp + 32], xmm3
            movdqu xmmword ptr [rsp + 48], xmm4
