            LOAD_STATE {state}, xmm14, xmm15, xmm5, xmm6
            movdqa xmm1, xmm14
            movdqa xmm2, xmm15

            movd xmm5, dword ptr [{pos}]
            movdqu xmm13, xmmword ptr [{digest}]
            pslldq xmm13, 4
            por xmm5, xmm13
            movdqu xmm6, xmmword ptr [{digest} + 12]
            movd xmm7, dword ptr [{digest} + 28]

            pshufb xmm5, xmmword ptr [{mask}]
            pshufb xmm6, xmmword ptr [{mask}]
            pshufb xmm7, xmmword ptr [{mask}]
            por xmm7, xmmword ptr [{pad}]
            movdqa xmm8, xmmword ptr [{len}]
            SINGLE_ROUNDS_64

            paddd xmm1, xmm14
            paddd xmm2, xmm15
