agree  varint varint_u16_write (512 inputs: original, A/A and shipped)
agree  varint varint_u16_read (512 inputs: original, A/A and shipped)
agree  varint varint_u16_size (512 inputs: original, A/A and shipped)
agree  varint varint_u32_write (512 inputs: original, A/A and shipped)
agree  varint varint_u32_read (512 inputs: original, A/A and shipped)
agree  varint varint_u32_size (512 inputs: original, A/A and shipped)
agree  varint varint_u64_write (512 inputs: original, A/A and shipped)
agree  varint varint_u64_read (512 inputs: original, A/A and shipped)
agree  varint varint_u64_size (512 inputs: original, A/A and shipped)
agree  varint varint_i16_write (512 inputs: original, A/A and shipped)
agree  varint varint_i16_read (512 inputs: original, A/A and shipped)
agree  varint varint_i16_size (512 inputs: original, A/A and shipped)
agree  varint varint_i32_write (512 inputs: original, A/A and shipped)
agree  varint varint_i32_read (512 inputs: original, A/A and shipped)
agree  varint varint_i32_size (512 inputs: original, A/A and shipped)
agree  varint varint_i64_write (512 inputs: original, A/A and shipped)
agree  varint varint_i64_read (512 inputs: original, A/A and shipped)
agree  varint varint_i64_size (512 inputs: original, A/A and shipped)
agree  varint varint_u64_decoder (512 inputs: original, A/A and shipped)
agree  varint varint_u32_decoder (512 inputs: original, A/A and shipped)
agree  mmr mmr_is_valid_size (512 inputs: original, A/A and shipped)
agree  mmr mmr_to_nearest_size (512 inputs: original, A/A and shipped)
agree  mmr mmr_location_to_position (512 inputs: original, A/A and shipped)
agree  mmr mmr_position_to_location (512 inputs: original, A/A and shipped)
agree  mmr mmr_peaks (512 inputs: original, A/A and shipped)
agree  mmr mmr_peak_iterator (512 inputs: original, A/A and shipped)
agree  mmr mmr_children (512 inputs: original, A/A and shipped)
agree  mmr mmr_parent_heights (512 inputs: original, A/A and shipped)
agree  mmr mmr_location_from_position (512 inputs: original, A/A and shipped)
agree  mmr mmr_position_from_location (512 inputs: original, A/A and shipped)
agree  verifier hasher_leaf_digest (512 inputs: original, A/A and shipped)
agree  verifier hasher_node_digest (512 inputs: original, A/A and shipped)
agree  verifier proof_verify_element_inclusion (512 inputs: original, A/A and shipped)
| set | function | original ns | A/A ns | shipped ns | A/A / original | shipped / original | shipped / original, rounds p10..p90 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| varint | varint_u16_write | 2.625 | 2.630 | 2.618 | 1.002 | 0.997 | 0.967..1.023 |
| varint | varint_u16_read | 1.531 | 1.500 | 1.505 | 0.980 | 0.983 | 0.957..0.991 |
| varint | varint_u16_size | 0.758 | 0.764 | 0.760 | 1.007 | 1.002 | 0.969..1.032 |
| varint | varint_u32_write | 3.234 | 3.242 | 3.232 | 1.003 | 0.999 | 0.972..1.008 |
| varint | varint_u32_read | 2.860 | 2.817 | 3.106 | 0.985 | 1.086 | 1.069..1.143 |
| varint | varint_u32_size | 0.742 | 0.742 | 0.742 | 1.000 | 1.000 | 0.987..1.027 |
| varint | varint_u64_write | 4.978 | 4.982 | 5.000 | 1.001 | 1.004 | 0.998..1.015 |
| varint | varint_u64_read | 3.515 | 3.604 | 3.618 | 1.025 | 1.029 | 1.014..1.059 |
| varint | varint_u64_size | 0.742 | 0.743 | 0.742 | 1.001 | 1.000 | 0.967..1.004 |
| varint | varint_i16_write | 2.747 | 2.740 | 2.745 | 0.997 | 0.999 | 0.955..1.028 |
| varint | varint_i16_read | 1.529 | 1.503 | 1.506 | 0.983 | 0.985 | 0.956..1.013 |
| varint | varint_i16_size | 0.954 | 0.954 | 0.954 | 1.000 | 1.000 | 1.000..1.071 |
| varint | varint_i32_write | 3.297 | 3.334 | 3.345 | 1.011 | 1.015 | 0.991..1.074 |
| varint | varint_i32_read | 2.883 | 2.845 | 2.876 | 0.987 | 0.997 | 0.969..1.050 |
| varint | varint_i32_size | 0.815 | 0.815 | 0.831 | 1.001 | 1.020 | 0.999..1.032 |
| varint | varint_i64_write | 5.062 | 5.060 | 5.049 | 1.000 | 0.997 | 0.962..1.007 |
| varint | varint_i64_read | 3.528 | 3.425 | 3.493 | 0.971 | 0.990 | 0.985..1.019 |
| varint | varint_i64_size | 0.984 | 0.983 | 0.983 | 0.998 | 0.999 | 0.968..0.999 |
| varint | varint_u64_decoder | 2.785 | 2.758 | 2.766 | 0.990 | 0.993 | 0.962..1.021 |
| varint | varint_u32_decoder | 2.077 | 2.085 | 2.104 | 1.004 | 1.013 | 1.004..1.026 |
| mmr | mmr_is_valid_size | 29.892 | 30.762 | 30.065 | 1.029 | 1.006 | 0.889..1.568 |
| mmr | mmr_to_nearest_size | 139.364 | 144.958 | 144.714 | 1.040 | 1.038 | 0.965..1.063 |
| mmr | mmr_location_to_position | 0.724 | 0.538 | 0.722 | 0.742 | 0.997 | 0.720..1.014 |
| mmr | mmr_position_to_location | 1.631 | 1.607 | 1.599 | 0.985 | 0.981 | 0.967..0.998 |
| mmr | mmr_peaks | 44.154 | 51.265 | 45.430 | 1.161 | 1.029 | 1.001..1.055 |
| mmr | mmr_peak_iterator | 42.908 | 46.382 | 44.220 | 1.081 | 1.031 | 0.999..1.047 |
| mmr | mmr_children | 0.506 | 0.505 | 0.505 | 1.000 | 0.999 | 0.964..1.031 |
| mmr | mmr_parent_heights | 1.687 | 1.671 | 1.677 | 0.990 | 0.994 | 0.974..1.004 |
| mmr | mmr_location_from_position | 3.060 | 3.167 | 3.263 | 1.035 | 1.066 | 1.034..1.067 |
| mmr | mmr_position_from_location | 1.134 | 1.141 | 1.133 | 1.006 | 0.999 | 0.969..1.020 |
| verifier | hasher_leaf_digest | 22.911 | 22.972 | 22.970 | 1.003 | 1.003 | 0.967..1.030 |
| verifier | hasher_node_digest | 52.185 | 51.158 | 52.195 | 0.980 | 1.000 | 0.979..1.043 |
| verifier | proof_verify_element_inclusion | 752.033 | 745.850 | 762.613 | 0.992 | 1.014 | 0.994..1.030 |
