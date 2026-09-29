            .macro LOAD_ROW dst, offset
            mov rax, qword ptr [r8 + \offset]
            vmovdqu32 \dst, zmmword ptr [rax]
            add rax, 64
            mov qword ptr [r8 + \offset], rax
            .endm

            .macro PAIR_DWORDS lo, hi
            vpunpckldq zmm0, \lo, \hi
            vpunpckhdq \hi, \lo, \hi
            vmovdqa32 \lo, zmm0
            .endm

            .macro TRANSPOSE_QUARTER out0, out4, out8, out12
            vshufi32x4 zmm0, \out0, \out8, 0x44
            vshufi32x4 zmm1, \out0, \out8, 0xee
            vshufi32x4 zmm2, \out4, \out12, 0x44
            vshufi32x4 zmm3, \out4, \out12, 0xee
            vshufi32x4 \out0, zmm0, zmm2, 0x88
            vshufi32x4 \out4, zmm0, zmm2, 0xdd
            vshufi32x4 \out8, zmm1, zmm3, 0x88
            vshufi32x4 \out12, zmm1, zmm3, 0xdd
            .endm

            .macro TRANSPOSE_16
            PAIR_DWORDS zmm16, zmm17
            PAIR_DWORDS zmm18, zmm19
            PAIR_DWORDS zmm20, zmm21
            PAIR_DWORDS zmm22, zmm23
            PAIR_DWORDS zmm24, zmm25
            PAIR_DWORDS zmm26, zmm27
            PAIR_DWORDS zmm28, zmm29
            PAIR_DWORDS zmm30, zmm31

            vpunpcklqdq zmm0, zmm16, zmm18
            vpunpckhqdq zmm1, zmm16, zmm18
            vpunpcklqdq zmm2, zmm17, zmm19
            vpunpckhqdq zmm3, zmm17, zmm19
            vmovdqa32 zmm16, zmm0
            vmovdqa32 zmm17, zmm1
            vmovdqa32 zmm18, zmm2
            vmovdqa32 zmm19, zmm3

            vpunpcklqdq zmm0, zmm28, zmm30
            vpunpckhqdq zmm1, zmm28, zmm30
            vpunpcklqdq zmm2, zmm29, zmm31
            vpunpckhqdq zmm3, zmm29, zmm31
            vmovdqa32 zmm28, zmm0
            vmovdqa32 zmm29, zmm1
            vmovdqa32 zmm30, zmm2
            vmovdqa32 zmm31, zmm3

            vpunpcklqdq zmm0, zmm20, zmm22
            vpunpckhqdq zmm1, zmm20, zmm22
            vpunpcklqdq zmm2, zmm21, zmm23
            vpunpckhqdq zmm3, zmm21, zmm23
            vpunpcklqdq zmm4, zmm24, zmm26
            vpunpckhqdq zmm5, zmm24, zmm26
            vpunpcklqdq zmm6, zmm25, zmm27
            vpunpckhqdq zmm7, zmm25, zmm27
            vmovdqa32 zmm24, zmm0
            vmovdqa32 zmm25, zmm1
            vmovdqa32 zmm26, zmm2
            vmovdqa32 zmm27, zmm3
            vmovdqa32 zmm20, zmm4
            vmovdqa32 zmm21, zmm5
            vmovdqa32 zmm22, zmm6
            vmovdqa32 zmm23, zmm7

            TRANSPOSE_QUARTER zmm16, zmm20, zmm24, zmm28
            TRANSPOSE_QUARTER zmm17, zmm21, zmm25, zmm29
            TRANSPOSE_QUARTER zmm18, zmm22, zmm26, zmm30
            TRANSPOSE_QUARTER zmm19, zmm23, zmm27, zmm31
            .endm

            .macro SHA256_ROUND a, b, c, d, e, f, g, h, word
            vpaddd zmm8, \h, \word
            vpaddd zmm8, zmm8, dword ptr [r9]{{1to16}}
            add r9, 4

            vprord zmm9, \e, 6
            vprord zmm10, \e, 11
            vprord zmm11, \e, 25
            vpternlogd zmm9, zmm10, zmm11, 0x96
            vpaddd zmm8, zmm8, zmm9

            vmovdqa32 zmm9, \e
            vpternlogd zmm9, \f, \g, 0xca
            vpaddd zmm8, zmm8, zmm9

            vprord zmm9, \a, 2
            vprord zmm10, \a, 13
            vprord zmm11, \a, 22
            vpternlogd zmm9, zmm10, zmm11, 0x96

            vmovdqa32 zmm10, \a
            vpternlogd zmm10, \b, \c, 0xe8
            vpaddd zmm9, zmm9, zmm10

            vpaddd \d, \d, zmm8
            vpaddd \h, zmm8, zmm9
            .endm

            .macro ROUNDS_8 w0, w1, w2, w3, w4, w5, w6, w7
            SHA256_ROUND zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, \w0
            SHA256_ROUND zmm7, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, \w1
            SHA256_ROUND zmm6, zmm7, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, \w2
            SHA256_ROUND zmm5, zmm6, zmm7, zmm0, zmm1, zmm2, zmm3, zmm4, \w3
            SHA256_ROUND zmm4, zmm5, zmm6, zmm7, zmm0, zmm1, zmm2, zmm3, \w4
            SHA256_ROUND zmm3, zmm4, zmm5, zmm6, zmm7, zmm0, zmm1, zmm2, \w5
            SHA256_ROUND zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm0, zmm1, \w6
            SHA256_ROUND zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm0, \w7
            .endm

            .macro SCHEDULE dst, w15, w7, w2
            vprord zmm12, \w2, 17
            vprord zmm13, \w2, 19
            vpsrld zmm14, \w2, 10
            vpternlogd zmm12, zmm13, zmm14, 0x96

            vprord zmm13, \w15, 7
            vprord zmm14, \w15, 18
            vpsrld zmm11, \w15, 3
            vpternlogd zmm13, zmm14, zmm11, 0x96

            vpaddd \dst, \dst, \w7
            vpaddd \dst, \dst, zmm12
            vpaddd \dst, \dst, zmm13
            .endm

            .macro SCHEDULE_ROUNDS_16
            SCHEDULE zmm16, zmm17, zmm25, zmm30
            SHA256_ROUND zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm16
            SCHEDULE zmm17, zmm18, zmm26, zmm31
            SHA256_ROUND zmm7, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm17
            SCHEDULE zmm18, zmm19, zmm27, zmm16
            SHA256_ROUND zmm6, zmm7, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm18
            SCHEDULE zmm19, zmm20, zmm28, zmm17
            SHA256_ROUND zmm5, zmm6, zmm7, zmm0, zmm1, zmm2, zmm3, zmm4, zmm19
            SCHEDULE zmm20, zmm21, zmm29, zmm18
            SHA256_ROUND zmm4, zmm5, zmm6, zmm7, zmm0, zmm1, zmm2, zmm3, zmm20
            SCHEDULE zmm21, zmm22, zmm30, zmm19
            SHA256_ROUND zmm3, zmm4, zmm5, zmm6, zmm7, zmm0, zmm1, zmm2, zmm21
            SCHEDULE zmm22, zmm23, zmm31, zmm20
            SHA256_ROUND zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm0, zmm1, zmm22
            SCHEDULE zmm23, zmm24, zmm16, zmm21
            SHA256_ROUND zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm0, zmm23
            SCHEDULE zmm24, zmm25, zmm17, zmm22
            SHA256_ROUND zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm24
            SCHEDULE zmm25, zmm26, zmm18, zmm23
            SHA256_ROUND zmm7, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm25
            SCHEDULE zmm26, zmm27, zmm19, zmm24
            SHA256_ROUND zmm6, zmm7, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm26
            SCHEDULE zmm27, zmm28, zmm20, zmm25
            SHA256_ROUND zmm5, zmm6, zmm7, zmm0, zmm1, zmm2, zmm3, zmm4, zmm27
            SCHEDULE zmm28, zmm29, zmm21, zmm26
            SHA256_ROUND zmm4, zmm5, zmm6, zmm7, zmm0, zmm1, zmm2, zmm3, zmm28
            SCHEDULE zmm29, zmm30, zmm22, zmm27
            SHA256_ROUND zmm3, zmm4, zmm5, zmm6, zmm7, zmm0, zmm1, zmm2, zmm29
            SCHEDULE zmm30, zmm31, zmm23, zmm28
            SHA256_ROUND zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm0, zmm1, zmm30
            SCHEDULE zmm31, zmm16, zmm24, zmm29
            SHA256_ROUND zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm0, zmm31
            .endm

            test {blocks}, {blocks}
            jz 9f
2:
            mov r8, {data}
            LOAD_ROW zmm16, 0
            LOAD_ROW zmm17, 8
            LOAD_ROW zmm18, 16
            LOAD_ROW zmm19, 24
            LOAD_ROW zmm20, 32
            LOAD_ROW zmm21, 40
            LOAD_ROW zmm22, 48
            LOAD_ROW zmm23, 56
            LOAD_ROW zmm24, 64
            LOAD_ROW zmm25, 72
            LOAD_ROW zmm26, 80
            LOAD_ROW zmm27, 88
            LOAD_ROW zmm28, 96
            LOAD_ROW zmm29, 104
            LOAD_ROW zmm30, 112
            LOAD_ROW zmm31, 120

            TRANSPOSE_16

            vmovdqu8 ymm15, ymmword ptr [{mask}]
            vshufi32x4 zmm15, zmm15, zmm15, 0x44
            vpshufb zmm16, zmm16, zmm15
            vpshufb zmm17, zmm17, zmm15
            vpshufb zmm18, zmm18, zmm15
            vpshufb zmm19, zmm19, zmm15
            vpshufb zmm20, zmm20, zmm15
            vpshufb zmm21, zmm21, zmm15
            vpshufb zmm22, zmm22, zmm15
            vpshufb zmm23, zmm23, zmm15
            vpshufb zmm24, zmm24, zmm15
            vpshufb zmm25, zmm25, zmm15
            vpshufb zmm26, zmm26, zmm15
            vpshufb zmm27, zmm27, zmm15
            vpshufb zmm28, zmm28, zmm15
            vpshufb zmm29, zmm29, zmm15
            vpshufb zmm30, zmm30, zmm15
            vpshufb zmm31, zmm31, zmm15

            vmovdqu32 zmm0, zmmword ptr [{state}]
            vmovdqu32 zmm1, zmmword ptr [{state} + 64]
            vmovdqu32 zmm2, zmmword ptr [{state} + 128]
            vmovdqu32 zmm3, zmmword ptr [{state} + 192]
            vmovdqu32 zmm4, zmmword ptr [{state} + 256]
            vmovdqu32 zmm5, zmmword ptr [{state} + 320]
            vmovdqu32 zmm6, zmmword ptr [{state} + 384]
            vmovdqu32 zmm7, zmmword ptr [{state} + 448]
            mov r9, {k}

            ROUNDS_8 zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23
            ROUNDS_8 zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31
            SCHEDULE_ROUNDS_16
            SCHEDULE_ROUNDS_16
            SCHEDULE_ROUNDS_16

            vpaddd zmm0, zmm0, zmmword ptr [{state}]
            vpaddd zmm1, zmm1, zmmword ptr [{state} + 64]
            vpaddd zmm2, zmm2, zmmword ptr [{state} + 128]
            vpaddd zmm3, zmm3, zmmword ptr [{state} + 192]
            vpaddd zmm4, zmm4, zmmword ptr [{state} + 256]
            vpaddd zmm5, zmm5, zmmword ptr [{state} + 320]
            vpaddd zmm6, zmm6, zmmword ptr [{state} + 384]
            vpaddd zmm7, zmm7, zmmword ptr [{state} + 448]
            vmovdqu32 zmmword ptr [{state}], zmm0
            vmovdqu32 zmmword ptr [{state} + 64], zmm1
            vmovdqu32 zmmword ptr [{state} + 128], zmm2
            vmovdqu32 zmmword ptr [{state} + 192], zmm3
            vmovdqu32 zmmword ptr [{state} + 256], zmm4
            vmovdqu32 zmmword ptr [{state} + 320], zmm5
            vmovdqu32 zmmword ptr [{state} + 384], zmm6
            vmovdqu32 zmmword ptr [{state} + 448], zmm7

            dec {blocks}
            jnz 2b
9:
            vzeroupper

            .purgem LOAD_ROW
            .purgem PAIR_DWORDS
            .purgem TRANSPOSE_QUARTER
            .purgem TRANSPOSE_16
            .purgem SHA256_ROUND
            .purgem ROUNDS_8
            .purgem SCHEDULE
            .purgem SCHEDULE_ROUNDS_16
