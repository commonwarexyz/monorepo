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
| varint | varint_u16_write | 2.632 | 2.633 | 2.619 | 1.000 | 0.995 | 0.989..1.007 |
| varint | varint_u16_read | 1.556 | 1.542 | 1.549 | 0.991 | 0.995 | 0.985..0.999 |
| varint | varint_u16_size | 0.779 | 0.784 | 0.774 | 1.007 | 0.994 | 0.971..1.008 |
| varint | varint_u32_write | 3.192 | 3.261 | 3.241 | 1.022 | 1.015 | 0.979..1.034 |
| varint | varint_u32_read | 1.818 | 1.844 | 1.842 | 1.015 | 1.013 | 0.987..1.051 |
| varint | varint_u32_size | 0.744 | 0.743 | 0.744 | 1.000 | 1.000 | 0.994..1.001 |
| varint | varint_u64_write | 4.986 | 4.997 | 4.992 | 1.002 | 1.001 | 0.991..1.015 |
| varint | varint_u64_read | 3.523 | 3.646 | 3.547 | 1.035 | 1.007 | 1.002..1.045 |
| varint | varint_u64_size | 0.720 | 0.720 | 0.720 | 1.001 | 1.000 | 0.970..1.018 |
| varint | varint_i16_write | 2.663 | 2.729 | 2.700 | 1.025 | 1.014 | 0.981..1.052 |
| varint | varint_i16_read | 1.577 | 1.577 | 1.551 | 1.000 | 0.983 | 0.971..0.996 |
| varint | varint_i16_size | 0.984 | 0.984 | 0.984 | 1.000 | 1.000 | 1.000..1.000 |
| varint | varint_i32_write | 3.316 | 3.319 | 3.319 | 1.001 | 1.001 | 0.984..1.012 |
| varint | varint_i32_read | 1.799 | 1.804 | 1.974 | 1.003 | 1.097 | 1.090..1.113 |
| varint | varint_i32_size | 0.952 | 0.952 | 0.952 | 1.000 | 1.000 | 1.000..1.000 |
| varint | varint_i64_write | 4.941 | 4.986 | 4.972 | 1.009 | 1.006 | 0.995..1.010 |
| varint | varint_i64_read | 3.365 | 3.376 | 3.389 | 1.003 | 1.007 | 1.003..1.013 |
| varint | varint_i64_size | 0.831 | 0.832 | 0.847 | 1.000 | 1.019 | 0.993..1.020 |
| varint | varint_u64_decoder | 2.667 | 2.689 | 2.646 | 1.008 | 0.992 | 0.988..1.001 |
| varint | varint_u32_decoder | 2.139 | 2.188 | 2.139 | 1.023 | 1.000 | 0.990..1.007 |
| mmr | mmr_is_valid_size | 29.587 | 29.378 | 29.694 | 0.993 | 1.004 | 0.977..1.017 |
| mmr | mmr_to_nearest_size | 147.095 | 151.530 | 147.542 | 1.030 | 1.003 | 0.994..1.007 |
| mmr | mmr_location_to_position | 0.750 | 0.748 | 0.749 | 0.997 | 0.999 | 0.997..1.012 |
| mmr | mmr_position_to_location | 2.450 | 2.525 | 2.835 | 1.031 | 1.157 | 1.107..1.189 |
| mmr | mmr_peaks | 54.596 | 48.106 | 49.316 | 0.881 | 0.903 | 0.844..1.181 |
| mmr | mmr_peak_iterator | 50.334 | 48.091 | 47.399 | 0.955 | 0.942 | 0.892..1.034 |
| mmr | mmr_children | 0.738 | 0.739 | 0.738 | 1.002 | 1.001 | 0.993..1.028 |
| mmr | mmr_parent_heights | 1.992 | 2.083 | 2.007 | 1.046 | 1.007 | 1.007..1.030 |
| mmr | mmr_location_from_position | 3.430 | 3.630 | 3.403 | 1.058 | 0.992 | 0.953..1.006 |
| mmr | mmr_position_from_location | 1.380 | 1.244 | 1.352 | 0.902 | 0.980 | 0.953..0.981 |
| verifier | hasher_leaf_digest | 23.415 | 23.435 | 23.435 | 1.001 | 1.001 | 0.997..1.005 |
| verifier | hasher_node_digest | 51.849 | 51.656 | 51.636 | 0.996 | 0.996 | 0.980..1.040 |
| verifier | proof_verify_element_inclusion | 740.641 | 736.328 | 746.906 | 0.994 | 1.008 | 0.985..1.025 |
