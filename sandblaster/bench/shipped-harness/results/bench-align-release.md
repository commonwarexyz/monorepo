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
| varint | varint_u16_write | 2.744 | 2.769 | 2.780 | 1.009 | 1.013 | 0.996..1.042 |
| varint | varint_u16_read | 1.510 | 1.500 | 1.504 | 0.993 | 0.996 | 0.943..1.054 |
| varint | varint_u16_size | 1.081 | 1.082 | 1.081 | 1.001 | 1.000 | 0.963..1.041 |
| varint | varint_u32_write | 3.410 | 3.410 | 3.407 | 1.000 | 0.999 | 0.971..1.045 |
| varint | varint_u32_read | 1.839 | 1.853 | 1.833 | 1.007 | 0.997 | 0.971..1.016 |
| varint | varint_u32_size | 1.020 | 1.020 | 1.019 | 1.000 | 0.999 | 0.857..1.147 |
| varint | varint_u64_write | 5.125 | 5.130 | 5.130 | 1.001 | 1.001 | 0.991..1.018 |
| varint | varint_u64_read | 3.693 | 3.675 | 3.680 | 0.995 | 0.996 | 0.932..1.025 |
| varint | varint_u64_size | 1.019 | 1.019 | 1.019 | 1.000 | 1.001 | 0.917..1.417 |
| varint | varint_i16_write | 2.847 | 2.858 | 2.863 | 1.004 | 1.006 | 0.921..1.067 |
| varint | varint_i16_read | 1.515 | 1.509 | 1.508 | 0.996 | 0.995 | 0.956..1.033 |
| varint | varint_i16_size | 1.375 | 1.416 | 1.405 | 1.030 | 1.022 | 0.943..1.260 |
| varint | varint_i32_write | 3.495 | 3.494 | 3.517 | 1.000 | 1.006 | 0.931..1.127 |
| varint | varint_i32_read | 1.835 | 1.850 | 1.852 | 1.008 | 1.009 | 0.977..1.038 |
| varint | varint_i32_size | 1.283 | 1.282 | 1.283 | 0.999 | 1.000 | 0.704..1.368 |
| varint | varint_i64_write | 5.252 | 5.259 | 5.249 | 1.001 | 1.000 | 0.993..1.017 |
| varint | varint_i64_read | 3.742 | 3.742 | 3.742 | 1.000 | 1.000 | 0.926..1.036 |
| varint | varint_i64_size | 1.283 | 1.280 | 1.279 | 0.998 | 0.998 | 0.648..1.192 |
| varint | varint_u64_decoder | 2.629 | 2.630 | 2.657 | 1.000 | 1.011 | 0.972..1.054 |
| varint | varint_u32_decoder | 2.039 | 2.047 | 2.058 | 1.004 | 1.009 | 0.980..1.060 |
| mmr | mmr_is_valid_size | 39.581 | 39.846 | 39.790 | 1.007 | 1.005 | 0.612..1.419 |
| mmr | mmr_to_nearest_size | 146.444 | 148.112 | 150.289 | 1.011 | 1.026 | 0.933..1.118 |
| mmr | mmr_location_to_position | 0.936 | 0.936 | 0.936 | 1.001 | 1.000 | 0.933..1.052 |
| mmr | mmr_position_to_location | 3.556 | 3.471 | 3.455 | 0.976 | 0.972 | 0.884..1.144 |
| mmr | mmr_peaks | 63.487 | 63.731 | 63.599 | 1.004 | 1.002 | 0.925..1.087 |
| mmr | mmr_peak_iterator | 62.358 | 62.337 | 62.836 | 1.000 | 1.008 | 0.923..1.050 |
| mmr | mmr_children | 0.772 | 0.772 | 0.771 | 1.000 | 0.999 | 0.642..1.002 |
| mmr | mmr_parent_heights | 2.064 | 2.050 | 2.060 | 0.993 | 0.998 | 0.982..1.008 |
| mmr | mmr_location_from_position | 4.698 | 4.662 | 4.810 | 0.992 | 1.024 | 0.804..1.344 |
| mmr | mmr_position_from_location | 1.467 | 1.468 | 1.468 | 1.001 | 1.000 | 0.900..1.034 |
| verifier | hasher_leaf_digest | 25.447 | 25.482 | 25.457 | 1.001 | 1.000 | 0.997..1.029 |
| verifier | hasher_node_digest | 50.313 | 50.395 | 49.673 | 1.002 | 0.987 | 0.958..1.029 |
| verifier | proof_verify_element_inclusion | 812.500 | 800.293 | 807.861 | 0.985 | 0.994 | 0.899..1.063 |
