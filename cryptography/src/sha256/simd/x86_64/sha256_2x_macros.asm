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
