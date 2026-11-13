            LOAD_STATE {state}, xmm14, xmm15, xmm5, xmm6
            movdqa xmm1, xmm14
            movdqa xmm2, xmm15

            movq xmm5, qword ptr [{pos}]
            movq xmm13, qword ptr [{left}]
            punpcklqdq xmm5, xmm13
            movdqu xmm6, xmmword ptr [{left} + 8]
            movq xmm7, qword ptr [{left} + 24]
            movq xmm13, qword ptr [{right}]
            punpcklqdq xmm7, xmm13
            movdqu xmm8, xmmword ptr [{right} + 8]

            pshufb xmm5, xmmword ptr [{mask}]
            pshufb xmm6, xmmword ptr [{mask}]
            pshufb xmm7, xmmword ptr [{mask}]
            pshufb xmm8, xmmword ptr [{mask}]
            SINGLE_ROUNDS_64

            paddd xmm1, xmm14
            paddd xmm2, xmm15
            movdqa xmm14, xmm1
            movdqa xmm15, xmm2

            movq xmm5, qword ptr [{right} + 24]
            pshufb xmm5, xmmword ptr [{mask}]
            por xmm5, xmmword ptr [{pad}]
            pxor xmm6, xmm6
            pxor xmm7, xmm7
            movdqa xmm8, xmmword ptr [{len}]
            SINGLE_ROUNDS_64

            paddd xmm1, xmm14
            paddd xmm2, xmm15
