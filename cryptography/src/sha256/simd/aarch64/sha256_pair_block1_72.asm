            ld1.4s {{v0, v1}}, [{state}]
            mov.16b v2, v0
            mov.16b v3, v1
            mov.16b v20, v0
            mov.16b v21, v1
            mov.16b v22, v2
            mov.16b v23, v3

            ld1 {{v4.d}}[0], [{left_pos}]
            ld1 {{v4.d}}[1], [{left_left}], #8
            ld1.16b {{v5}}, [{left_left}], #16
            ld1 {{v6.d}}[0], [{left_left}]
            ld1 {{v6.d}}[1], [{left_right}], #8
            ld1.16b {{v7}}, [{left_right}], #16

            ld1 {{v8.d}}[0], [{right_pos}]
            ld1 {{v8.d}}[1], [{right_left}], #8
            ld1.16b {{v9}}, [{right_left}], #16
            ld1 {{v10.d}}[0], [{right_left}]
            ld1 {{v10.d}}[1], [{right_right}], #8
            ld1.16b {{v11}}, [{right_right}], #16

            rev32.16b v4, v4
            rev32.16b v5, v5
            rev32.16b v6, v6
            rev32.16b v7, v7
            rev32.16b v8, v8
            rev32.16b v9, v9
            rev32.16b v10, v10
            rev32.16b v11, v11
            mov {k}, {k_start}
