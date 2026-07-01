            .macro STORE_DIGEST output, offset, abef, cdgh, tmp0, tmp1, tmp2
            pshufd \tmp0, \abef, 27
            pshufd \tmp1, \cdgh, 177
            movdqa \tmp2, \tmp0
            pblendw \tmp2, \tmp1, 240
            palignr \tmp1, \tmp0, 8
            pshufb \tmp2, xmmword ptr [{mask}]
            pshufb \tmp1, xmmword ptr [{mask}]
            movdqu xmmword ptr [\output + \offset], \tmp2
            movdqu xmmword ptr [\output + \offset + 16], \tmp1
            .endm

            .macro ROUNDS_64
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
            .endm

            .macro ADD_SAVED_STATE
            paddd xmm1, xmmword ptr [rsp]
            paddd xmm2, xmmword ptr [rsp + 16]
            paddd xmm3, xmmword ptr [rsp + 32]
            paddd xmm4, xmmword ptr [rsp + 48]
            .endm

            .macro ADD_INITIAL_STATE
            paddd xmm1, xmm14
            paddd xmm2, xmm15
            paddd xmm3, xmm14
            paddd xmm4, xmm15
            .endm

            .macro SAVE_STATE
            movdqu xmmword ptr [rsp], xmm1
            movdqu xmmword ptr [rsp + 16], xmm2
            movdqu xmmword ptr [rsp + 32], xmm3
            movdqu xmmword ptr [rsp + 48], xmm4
            .endm

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
            ADD_INITIAL_STATE

            sub rsp, 64
            SAVE_STATE

            pxor xmm5, xmm5
            pxor xmm6, xmm6
            pxor xmm7, xmm7
            movq xmm5, qword ptr [{left} + 64]
            pshufb xmm5, xmmword ptr [{mask}]
            por xmm5, xmmword ptr [{pad}]
            movdqa xmm8, xmmword ptr [{len}]

            pxor xmm9, xmm9
            pxor xmm10, xmm10
            pxor xmm11, xmm11
            movq xmm9, qword ptr [{right} + 64]
            pshufb xmm9, xmmword ptr [{mask}]
            por xmm9, xmmword ptr [{pad}]
            movdqa xmm12, xmmword ptr [{len}]

            ROUNDS_64
            ADD_SAVED_STATE

            STORE_DIGEST {output}, 0, xmm1, xmm2, xmm5, xmm6, xmm7
            STORE_DIGEST {output}, 32, xmm3, xmm4, xmm5, xmm6, xmm7
            add rsp, 64

            .purgem LOAD_STATE
            .purgem STORE_DIGEST
            .purgem ROUNDS4
            .purgem SCHEDULE
            .purgem PAIR_ROUNDS4
            .purgem ROUNDS_64
            .purgem ADD_SAVED_STATE
            .purgem ADD_INITIAL_STATE
            .purgem SAVE_STATE
