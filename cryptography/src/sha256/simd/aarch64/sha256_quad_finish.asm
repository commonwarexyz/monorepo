            add.4s v0, v0, v8
            add.4s v1, v1, v9
            add.4s v2, v2, v10
            add.4s v3, v3, v11
            add.4s v4, v4, v12
            add.4s v5, v5, v13
            add.4s v6, v6, v14
            add.4s v7, v7, v15
            .irp n,0,1,2,3,4,5,6,7
                rev32.16b v\n, v\n
            .endr
            st1.16b {{v0, v1, v2, v3}}, [{output}], #64
            st1.16b {{v4, v5, v6, v7}}, [{output}]
