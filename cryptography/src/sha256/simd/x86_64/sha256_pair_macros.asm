            .macro LOAD_STATE state, abef, cdgh, tmp0, tmp1
            movdqu \tmp0, xmmword ptr [\state]
            movdqu \tmp1, xmmword ptr [\state + 16]
            pshufd \tmp0, \tmp0, 177
            pshufd \tmp1, \tmp1, 27
            movdqa \abef, \tmp0
            palignr \abef, \tmp1, 8
            pblendw \tmp1, \tmp0, 240
            movdqa \cdgh, \tmp1
            .endm

            .macro STORE_DIGEST output, abef, cdgh, tmp0, tmp1, tmp2
            pshufd \tmp0, \abef, 27
            pshufd \tmp1, \cdgh, 177
            movdqa \tmp2, \tmp0
            pblendw \tmp2, \tmp1, 240
            palignr \tmp1, \tmp0, 8
            pshufb \tmp2, xmmword ptr [{mask}]
            pshufb \tmp1, xmmword ptr [{mask}]
            movdqu xmmword ptr [\output], \tmp2
            movdqu xmmword ptr [\output + 16], \tmp1
            .endm

            .macro ROUNDS4 abef, cdgh, schedule, offset
            vpaddd xmm0, \schedule, xmmword ptr [{k} + \offset]
            sha256rnds2 \cdgh, \abef, xmm0
            vpshufd xmm0, xmm0, 14
            sha256rnds2 \abef, \cdgh, xmm0
            .endm

            .macro SCHEDULE dst, next, prev2, prev3, tmp
            sha256msg1 \dst, \next
            movdqa \tmp, \prev3
            palignr \tmp, \prev2, 4
            paddd \dst, \tmp
            sha256msg2 \dst, \prev3
            .endm

            .macro PAIR_ROUNDS4 left_schedule, right_schedule, offset
            ROUNDS4 xmm1, xmm2, \left_schedule, \offset
            ROUNDS4 xmm3, xmm4, \right_schedule, \offset
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
