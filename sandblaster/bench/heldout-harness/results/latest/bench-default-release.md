agree  H1 decimal_digits (512 inputs: rustc, A/A and optimized)
agree  H1 base32_encoded_len (512 inputs: rustc, A/A and optimized)
agree  H1 base64_encoded_len (512 inputs: rustc, A/A and optimized)
agree  H1 reverse_bits (512 inputs: rustc, A/A and optimized)
agree  H1 gray_encode (512 inputs: rustc, A/A and optimized)
agree  H1 gray_decode (512 inputs: rustc, A/A and optimized)
agree  H1 next_power_of_two (512 inputs: rustc, A/A and optimized)
agree  H1 isqrt (512 inputs: rustc, A/A and optimized)
agree  H1 fenwick_prefix_sum (512 inputs: rustc, A/A and optimized)
agree  H1 buddy_order (512 inputs: rustc, A/A and optimized)
agree  H1 binomial_meld_carries (512 inputs: rustc, A/A and optimized)
agree  H1 hamming_distance (512 inputs: rustc, A/A and optimized)
agree  H1 run_count (512 inputs: rustc, A/A and optimized)
agree  H1 first_newline (512 inputs: rustc, A/A and optimized)
agree  H1 first_printable (512 inputs: rustc, A/A and optimized)
agree  H1 checked_sum (512 inputs: rustc, A/A and optimized)
agree  H1 ring_index (512 inputs: rustc, A/A and optimized)
agree  H1 align_up (512 inputs: rustc, A/A and optimized)
agree  H1 ceil_div (512 inputs: rustc, A/A and optimized)
agree  H1 crc8 (512 inputs: rustc, A/A and optimized)
agree  H1 parity (512 inputs: rustc, A/A and optimized)
agree  H1 trailing_ones (512 inputs: rustc, A/A and optimized)
agree  H1 byte_swap (512 inputs: rustc, A/A and optimized)
agree  H1 nibble_popcount (512 inputs: rustc, A/A and optimized)
agree  H1 matrix_sum_4x8 (512 inputs: rustc, A/A and optimized)
agree  H1 seed16_rounds20 (512 inputs: rustc, A/A and optimized)
agree  H1 count_words (512 inputs: rustc, A/A and optimized)
agree  H1 scale_sample (512 inputs: rustc, A/A and optimized)
agree  H1 remaining_budget (512 inputs: rustc, A/A and optimized)
agree  H1 read_u32_le (512 inputs: rustc, A/A and optimized)
agree  H2 mix64 (512 inputs: rustc, A/A and optimized)
| set | function | rustc ns | A/A ns | optimized ns | A/A / rustc | optimized / rustc | optimized / rustc, rounds p10..p90 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| H1 | decimal_digits | 3.570 | 4.608 | 3.394 | 1.291 | 0.951 | 0.949..0.953 |
| H1 | base32_encoded_len | 1.136 | 1.265 | 1.265 | 1.114 | 1.114 | 1.081..1.206 |
| H1 | base64_encoded_len | 1.417 | 1.457 | 1.318 | 1.028 | 0.930 | 0.903..0.926 |
| H1 | reverse_bits | 0.504 | 0.504 | 0.504 | 1.000 | 1.000 | 0.971..1.000 |
| H1 | gray_encode | 0.505 | 0.505 | 0.505 | 1.000 | 1.000 | 0.999..1.003 |
| H1 | gray_decode | 5.185 | 5.033 | 5.850 | 0.971 | 1.128 | 1.127..1.258 |
| H1 | next_power_of_two | 0.965 | 0.957 | 0.964 | 0.992 | 0.999 | 0.995..1.008 |
| H1 | isqrt | 23.020 | 23.750 | 23.099 | 1.032 | 1.003 | 0.998..1.048 |
| H1 | fenwick_prefix_sum | 1.976 | 1.894 | 1.932 | 0.958 | 0.977 | 0.970..0.982 |
| H1 | buddy_order | 4.283 | 4.213 | 4.524 | 0.984 | 1.056 | 1.035..1.087 |
| H1 | binomial_meld_carries | 28.788 | 29.434 | 29.312 | 1.022 | 1.018 | 0.999..1.023 |
| H1 | hamming_distance | 12.581 | 13.092 | 13.285 | 1.041 | 1.056 | 1.036..1.088 |
| H1 | run_count | 20.785 | 21.924 | 21.286 | 1.055 | 1.024 | 1.023..1.024 |
| H1 | first_newline | 5.906 | 5.603 | 5.545 | 0.949 | 0.939 | 0.938..0.940 |
| H1 | first_printable | 2.007 | 2.034 | 2.029 | 1.014 | 1.011 | 1.008..1.014 |
| H1 | checked_sum | 5.386 | 5.442 | 5.377 | 1.011 | 0.998 | 0.985..1.017 |
| H1 | ring_index | 0.815 | 0.809 | 0.821 | 0.993 | 1.007 | 0.959..1.056 |
| H1 | align_up | 0.747 | 0.744 | 0.745 | 0.996 | 0.997 | 0.984..0.998 |
| H1 | ceil_div | 0.858 | 1.091 | 0.841 | 1.271 | 0.980 | 0.952..0.981 |
| H1 | crc8 | 21.645 | 21.604 | 21.698 | 0.998 | 1.002 | 0.973..1.027 |
| H1 | parity | 3.190 | 3.265 | 3.183 | 1.024 | 0.998 | 0.996..1.006 |
| H1 | trailing_ones | 1.748 | 1.743 | 1.730 | 0.997 | 0.990 | 0.987..1.017 |
| H1 | byte_swap | 0.489 | 0.489 | 0.490 | 1.000 | 1.001 | 0.978..1.006 |
| H1 | nibble_popcount | 0.661 | 0.661 | 0.661 | 1.000 | 1.000 | 0.961..1.015 |
| H1 | matrix_sum_4x8 | 0.509 | 0.509 | 0.509 | 1.000 | 1.000 | 0.999..1.001 |
| H1 | seed16_rounds20 | 12.123 | 12.123 | 12.118 | 1.000 | 1.000 | 0.999..1.000 |
| H1 | count_words | 19.897 | 19.814 | 20.020 | 0.996 | 1.006 | 1.000..1.007 |
| H1 | scale_sample | 1.116 | 1.116 | 1.116 | 1.000 | 1.000 | 0.973..1.044 |
| H1 | remaining_budget | 6.161 | 5.051 | 5.143 | 0.820 | 0.835 | 0.829..0.837 |
| H1 | read_u32_le | 1.151 | 1.197 | 1.242 | 1.040 | 1.079 | 1.072..1.081 |
| H2 | mix64 | 0.738 | 0.731 | 0.738 | 0.991 | 1.000 | 0.957..1.011 |
