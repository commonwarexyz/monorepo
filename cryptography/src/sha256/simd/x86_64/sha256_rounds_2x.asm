            .macro STORE_STATE state, abef, cdgh, tmp0, tmp1, tmp2
            pshufd \tmp0, \abef, 27
            pshufd \tmp1, \cdgh, 177
            movdqa \tmp2, \tmp0
            pblendw \tmp2, \tmp1, 240
            palignr \tmp1, \tmp0, 8
            movdqu xmmword ptr [\state], \tmp2
            movdqu xmmword ptr [\state + 16], \tmp1
            .endm

            LOAD_STATE {left_state}, xmm1, xmm2, xmm5, xmm6
            LOAD_STATE {right_state}, xmm3, xmm4, xmm5, xmm6
            sub rsp, 64

        2:
            movdqu xmmword ptr [rsp], xmm1
            movdqu xmmword ptr [rsp + 16], xmm2
            movdqu xmmword ptr [rsp + 32], xmm3
            movdqu xmmword ptr [rsp + 48], xmm4

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

            PAIR_ROUNDS4 xmm5, xmm9, 0
            PAIR_ROUNDS4 xmm6, xmm10, 16
            PAIR_ROUNDS4 xmm7, xmm11, 32
            PAIR_ROUNDS4 xmm8, xmm12, 48

            SCHEDULE xmm5, xmm6, xmm7, xmm8, xmm13
            SCHEDULE xmm9, xmm10, xmm11, xmm12, xmm13
            PAIR_ROUNDS4 xmm5, xmm9, 64

            SCHEDULE xmm6, xmm7, xmm8, xmm5, xmm13
            SCHEDULE xmm10, xmm11, xmm12, xmm9, xmm13
            PAIR_ROUNDS4 xmm6, xmm10, 80

            SCHEDULE xmm7, xmm8, xmm5, xmm6, xmm13
            SCHEDULE xmm11, xmm12, xmm9, xmm10, xmm13
            PAIR_ROUNDS4 xmm7, xmm11, 96

            SCHEDULE xmm8, xmm5, xmm6, xmm7, xmm13
            SCHEDULE xmm12, xmm9, xmm10, xmm11, xmm13
            PAIR_ROUNDS4 xmm8, xmm12, 112

            SCHEDULE xmm5, xmm6, xmm7, xmm8, xmm13
            SCHEDULE xmm9, xmm10, xmm11, xmm12, xmm13
            PAIR_ROUNDS4 xmm5, xmm9, 128

            SCHEDULE xmm6, xmm7, xmm8, xmm5, xmm13
            SCHEDULE xmm10, xmm11, xmm12, xmm9, xmm13
            PAIR_ROUNDS4 xmm6, xmm10, 144

            SCHEDULE xmm7, xmm8, xmm5, xmm6, xmm13
            SCHEDULE xmm11, xmm12, xmm9, xmm10, xmm13
            PAIR_ROUNDS4 xmm7, xmm11, 160

            SCHEDULE xmm8, xmm5, xmm6, xmm7, xmm13
            SCHEDULE xmm12, xmm9, xmm10, xmm11, xmm13
            PAIR_ROUNDS4 xmm8, xmm12, 176

            SCHEDULE xmm5, xmm6, xmm7, xmm8, xmm13
            SCHEDULE xmm9, xmm10, xmm11, xmm12, xmm13
            PAIR_ROUNDS4 xmm5, xmm9, 192

            SCHEDULE xmm6, xmm7, xmm8, xmm5, xmm13
            SCHEDULE xmm10, xmm11, xmm12, xmm9, xmm13
            PAIR_ROUNDS4 xmm6, xmm10, 208

            SCHEDULE xmm7, xmm8, xmm5, xmm6, xmm13
            SCHEDULE xmm11, xmm12, xmm9, xmm10, xmm13
            PAIR_ROUNDS4 xmm7, xmm11, 224

            SCHEDULE xmm8, xmm5, xmm6, xmm7, xmm13
            SCHEDULE xmm12, xmm9, xmm10, xmm11, xmm13
            PAIR_ROUNDS4 xmm8, xmm12, 240

            paddd xmm1, xmmword ptr [rsp]
            paddd xmm2, xmmword ptr [rsp + 16]
            paddd xmm3, xmmword ptr [rsp + 32]
            paddd xmm4, xmmword ptr [rsp + 48]

            add {left}, 64
            add {right}, 64
            dec {blocks}
            jne 2b

            STORE_STATE {left_state}, xmm1, xmm2, xmm5, xmm6, xmm7
            STORE_STATE {right_state}, xmm3, xmm4, xmm5, xmm6, xmm7
            add rsp, 64

            .purgem LOAD_STATE
            .purgem STORE_STATE
            .purgem ROUNDS4
            .purgem SCHEDULE
            .purgem PAIR_ROUNDS4
