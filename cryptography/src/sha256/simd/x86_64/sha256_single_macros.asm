            .macro SINGLE_ROUNDS_64
            ROUNDS4 xmm1, xmm2, xmm5, 0
            ROUNDS4 xmm1, xmm2, xmm6, 16
            ROUNDS4 xmm1, xmm2, xmm7, 32
            ROUNDS4 xmm1, xmm2, xmm8, 48

            SCHEDULE xmm5, xmm6, xmm7, xmm8, xmm13
            ROUNDS4 xmm1, xmm2, xmm5, 64

            SCHEDULE xmm6, xmm7, xmm8, xmm5, xmm13
            ROUNDS4 xmm1, xmm2, xmm6, 80

            SCHEDULE xmm7, xmm8, xmm5, xmm6, xmm13
            ROUNDS4 xmm1, xmm2, xmm7, 96

            SCHEDULE xmm8, xmm5, xmm6, xmm7, xmm13
            ROUNDS4 xmm1, xmm2, xmm8, 112

            SCHEDULE xmm5, xmm6, xmm7, xmm8, xmm13
            ROUNDS4 xmm1, xmm2, xmm5, 128

            SCHEDULE xmm6, xmm7, xmm8, xmm5, xmm13
            ROUNDS4 xmm1, xmm2, xmm6, 144

            SCHEDULE xmm7, xmm8, xmm5, xmm6, xmm13
            ROUNDS4 xmm1, xmm2, xmm7, 160

            SCHEDULE xmm8, xmm5, xmm6, xmm7, xmm13
            ROUNDS4 xmm1, xmm2, xmm8, 176

            SCHEDULE xmm5, xmm6, xmm7, xmm8, xmm13
            ROUNDS4 xmm1, xmm2, xmm5, 192

            SCHEDULE xmm6, xmm7, xmm8, xmm5, xmm13
            ROUNDS4 xmm1, xmm2, xmm6, 208

            SCHEDULE xmm7, xmm8, xmm5, xmm6, xmm13
            ROUNDS4 xmm1, xmm2, xmm7, 224

            SCHEDULE xmm8, xmm5, xmm6, xmm7, xmm13
            ROUNDS4 xmm1, xmm2, xmm8, 240
            .endm
