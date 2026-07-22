            ROUNDS_64

            paddd xmm1, xmmword ptr [rsp]
            paddd xmm2, xmmword ptr [rsp + 16]
            paddd xmm3, xmmword ptr [rsp + 32]
            paddd xmm4, xmmword ptr [rsp + 48]

            STORE_DIGEST {left_output}, xmm1, xmm2, xmm5, xmm6, xmm7
            STORE_DIGEST {right_output}, xmm3, xmm4, xmm5, xmm6, xmm7
            add rsp, 64

            .purgem LOAD_STATE
            .purgem STORE_DIGEST
            .purgem ROUNDS4
            .purgem SCHEDULE
            .purgem PAIR_ROUNDS4
            .purgem ROUNDS_64
