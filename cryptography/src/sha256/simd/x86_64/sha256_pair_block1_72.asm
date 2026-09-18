            LOAD_STATE {state}, xmm14, xmm15, xmm5, xmm6
            movdqa xmm1, xmm14
            movdqa xmm2, xmm15
            movdqa xmm3, xmm14
            movdqa xmm4, xmm15

            movq xmm5, qword ptr [{left_pos}]
            movq xmm13, qword ptr [{left_left}]
            punpcklqdq xmm5, xmm13
            movdqu xmm6, xmmword ptr [{left_left} + 8]
            movq xmm7, qword ptr [{left_left} + 24]
            movq xmm13, qword ptr [{left_right}]
            punpcklqdq xmm7, xmm13
            movdqu xmm8, xmmword ptr [{left_right} + 8]

            movq xmm9, qword ptr [{right_pos}]
            movq xmm13, qword ptr [{right_left}]
            punpcklqdq xmm9, xmm13
            movdqu xmm10, xmmword ptr [{right_left} + 8]
            movq xmm11, qword ptr [{right_left} + 24]
            movq xmm13, qword ptr [{right_right}]
            punpcklqdq xmm11, xmm13
            movdqu xmm12, xmmword ptr [{right_right} + 8]

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
