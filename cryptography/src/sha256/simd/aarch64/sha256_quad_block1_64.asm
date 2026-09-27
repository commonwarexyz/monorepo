            ld1.4s {{v0, v1}}, [{state}]
            mov.16b v2, v0
            mov.16b v3, v1
            mov.16b v4, v0
            mov.16b v5, v1
            mov.16b v6, v0
            mov.16b v7, v1

            ld1.16b {{v8, v9}}, [{left_0}]
            ld1.16b {{v10, v11}}, [{right_0}]
            ld1.16b {{v12, v13}}, [{left_1}]
            ld1.16b {{v14, v15}}, [{right_1}]
            ld1.16b {{v16, v17}}, [{left_2}]
            ld1.16b {{v18, v19}}, [{right_2}]
            ld1.16b {{v20, v21}}, [{left_3}]
            ld1.16b {{v22, v23}}, [{right_3}]
            .irp n,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
                rev32.16b v\n, v\n
            .endr
