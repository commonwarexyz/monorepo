            pxor xmm5, xmm5
            pxor xmm6, xmm6
            pxor xmm7, xmm7
            movq xmm5, qword ptr [{left_right} + 24]
            pshufb xmm5, xmmword ptr [{mask}]
            por xmm5, xmmword ptr [{pad}]
            movdqa xmm8, xmmword ptr [{len}]

            pxor xmm9, xmm9
            pxor xmm10, xmm10
            pxor xmm11, xmm11
            movq xmm9, qword ptr [{right_right} + 24]
            pshufb xmm9, xmmword ptr [{mask}]
            por xmm9, xmmword ptr [{pad}]
            movdqa xmm12, xmmword ptr [{len}]
