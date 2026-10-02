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
| H1 | decimal_digits | 3.412 | 3.899 | 3.412 | 1.143 | 1.000 | 0.985..1.027 |
| H1 | base32_encoded_len | 1.209 | 1.129 | 1.206 | 0.933 | 0.997 | 0.986..1.112 |
| H1 | base64_encoded_len | 1.351 | 1.247 | 1.351 | 0.923 | 1.000 | 0.914..1.087 |
| H1 | reverse_bits | 0.481 | 0.482 | 0.481 | 1.001 | 0.999 | 0.994..1.007 |
| H1 | gray_encode | 0.484 | 0.484 | 0.484 | 1.000 | 1.000 | 0.993..1.008 |
| H1 | gray_decode | 5.110 | 9.151 | 5.592 | 1.791 | 1.094 | 1.059..1.126 |
| H1 | next_power_of_two | 0.975 | 0.921 | 0.925 | 0.945 | 0.949 | 0.926..0.965 |
| H1 | isqrt | 22.797 | 22.619 | 23.209 | 0.992 | 1.018 | 1.005..1.026 |
| H1 | fenwick_prefix_sum | 1.814 | 1.926 | 1.966 | 1.062 | 1.084 | 1.058..1.091 |
| H1 | buddy_order | 4.193 | 4.047 | 4.059 | 0.965 | 0.968 | 0.942..0.986 |
| H1 | binomial_meld_carries | 26.174 | 28.661 | 31.062 | 1.095 | 1.187 | 1.172..1.220 |
| H1 | hamming_distance | 13.397 | 12.014 | 11.787 | 0.897 | 0.880 | 0.863..0.883 |
| H1 | run_count | 20.849 | 21.004 | 20.632 | 1.007 | 0.990 | 0.979..1.016 |
| H1 | first_newline | 5.777 | 5.999 | 5.402 | 1.038 | 0.935 | 0.917..0.956 |
| H1 | first_printable | 2.033 | 2.024 | 2.220 | 0.996 | 1.092 | 1.075..1.104 |
| H1 | checked_sum | 5.267 | 5.236 | 5.306 | 0.994 | 1.007 | 0.994..1.037 |
| H1 | ring_index | 0.748 | 0.754 | 0.748 | 1.008 | 0.999 | 0.980..1.011 |
| H1 | align_up | 0.711 | 0.711 | 0.711 | 1.000 | 1.000 | 0.992..1.005 |
| H1 | ceil_div | 0.841 | 0.937 | 1.369 | 1.114 | 1.628 | 1.618..1.661 |
| H1 | crc8 | 21.103 | 21.345 | 21.673 | 1.011 | 1.027 | 1.019..1.033 |
| H1 | parity | 3.126 | 3.489 | 3.170 | 1.116 | 1.014 | 0.988..1.020 |
| H1 | trailing_ones | 1.728 | 1.745 | 1.719 | 1.010 | 0.995 | 0.974..1.017 |
| H1 | byte_swap | 0.484 | 0.484 | 0.485 | 1.000 | 1.002 | 0.991..1.009 |
| H1 | nibble_popcount | 0.581 | 0.586 | 0.587 | 1.008 | 1.010 | 0.995..1.018 |
| H1 | matrix_sum_4x8 | 0.488 | 0.488 | 0.489 | 0.999 | 1.001 | 0.989..1.016 |
| H1 | seed16_rounds20 | 12.001 | 11.987 | 11.978 | 0.999 | 0.998 | 0.986..1.006 |
| H1 | count_words | 19.760 | 19.656 | 19.623 | 0.995 | 0.993 | 0.843..1.013 |
| H1 | scale_sample | 1.068 | 1.066 | 1.063 | 0.998 | 0.996 | 0.985..1.108 |
| H1 | remaining_budget | 6.941 | 4.884 | 6.448 | 0.704 | 0.929 | 0.858..1.030 |
| H1 | read_u32_le | 1.146 | 1.193 | 1.143 | 1.041 | 0.998 | 0.974..1.019 |
| H2 | mix64 | 0.714 | 0.711 | 0.712 | 0.997 | 0.997 | 0.978..1.018 |
