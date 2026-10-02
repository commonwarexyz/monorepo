            ld1.4s {{v24, v25}}, [{state}]
            .irp n,0,2,4,6
                add.4s v\n, v\n, v24
            .endr
            .irp n,1,3,5,7
                add.4s v\n, v\n, v25
            .endr

            // The padding block's schedule comes from a table, so the
            // schedule registers hold the chaining values.
            mov.16b v8, v0
            mov.16b v9, v1
            mov.16b v10, v2
            mov.16b v11, v3
            mov.16b v12, v4
            mov.16b v13, v5
            mov.16b v14, v6
            mov.16b v15, v7
