            add.4s v0, v0, v20
            add.4s v1, v1, v21
            add.4s v2, v2, v22
            add.4s v3, v3, v23
            rev32.16b v0, v0
            rev32.16b v1, v1
            rev32.16b v2, v2
            rev32.16b v3, v3
            st1.16b {{v0, v1}}, [{left_output}]
            st1.16b {{v2, v3}}, [{right_output}]
