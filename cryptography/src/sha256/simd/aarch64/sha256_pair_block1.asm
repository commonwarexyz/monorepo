            ld1.4s {{v0, v1}}, [{state}]
            mov.16b v2, v0
            mov.16b v3, v1
            mov.16b v20, v0
            mov.16b v21, v1
            mov.16b v22, v2
            mov.16b v23, v3

            ld1.16b {{v4, v5, v6, v7}}, [{left}], #64
            ld1.16b {{v8, v9, v10, v11}}, [{right}], #64
            rev32.16b v4, v4
            rev32.16b v5, v5
            rev32.16b v6, v6
            rev32.16b v7, v7
            rev32.16b v8, v8
            rev32.16b v9, v9
            rev32.16b v10, v10
            rev32.16b v11, v11
            mov {k}, {k_start}
