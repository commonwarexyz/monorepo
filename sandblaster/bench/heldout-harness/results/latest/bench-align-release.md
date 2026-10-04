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
| H1 | decimal_digits | 3.880 | 3.829 | 3.848 | 0.987 | 0.992 | 0.941..1.011 |
| H1 | base32_encoded_len | 1.272 | 1.272 | 1.240 | 1.000 | 0.975 | 0.884..1.112 |
| H1 | base64_encoded_len | 1.377 | 1.410 | 1.434 | 1.023 | 1.041 | 0.934..1.111 |
| H1 | reverse_bits | 0.505 | 0.507 | 0.505 | 1.003 | 1.000 | 0.971..1.020 |
| H1 | gray_encode | 0.505 | 0.511 | 0.505 | 1.011 | 1.000 | 0.938..1.016 |
| H1 | gray_decode | 5.168 | 5.135 | 5.155 | 0.993 | 0.997 | 0.973..1.027 |
| H1 | next_power_of_two | 0.978 | 0.980 | 0.980 | 1.003 | 1.003 | 0.974..1.034 |
| H1 | isqrt | 23.794 | 23.933 | 23.977 | 1.006 | 1.008 | 0.974..1.053 |
| H1 | fenwick_prefix_sum | 1.949 | 1.953 | 1.997 | 1.002 | 1.025 | 0.982..1.058 |
| H1 | buddy_order | 4.300 | 4.290 | 4.731 | 0.997 | 1.100 | 1.052..1.123 |
| H1 | binomial_meld_carries | 31.372 | 29.638 | 29.694 | 0.945 | 0.946 | 0.877..1.152 |
| H1 | hamming_distance | 13.306 | 13.125 | 13.626 | 0.986 | 1.024 | 0.981..1.071 |
| H1 | run_count | 21.301 | 21.502 | 21.390 | 1.009 | 1.004 | 0.975..1.090 |
| H1 | first_newline | 5.662 | 5.683 | 5.852 | 1.004 | 1.034 | 0.979..1.075 |
| H1 | first_printable | 2.058 | 2.049 | 2.048 | 0.996 | 0.995 | 0.974..1.023 |
| H1 | checked_sum | 5.810 | 5.747 | 5.559 | 0.989 | 0.957 | 0.928..1.047 |
| H1 | ring_index | 0.808 | 0.807 | 0.808 | 0.999 | 1.000 | 1.000..1.000 |
| H1 | align_up | 0.767 | 0.768 | 0.767 | 1.001 | 1.000 | 1.000..1.000 |
| H1 | ceil_div | 0.867 | 0.867 | 0.867 | 1.000 | 1.000 | 0.998..1.022 |
| H1 | crc8 | 22.552 | 22.565 | 22.560 | 1.001 | 1.000 | 0.998..1.006 |
| H1 | parity | 3.290 | 3.272 | 3.290 | 0.994 | 1.000 | 0.999..1.001 |
| H1 | trailing_ones | 1.783 | 1.787 | 1.776 | 1.002 | 0.996 | 0.993..1.022 |
| H1 | byte_swap | 0.504 | 0.495 | 0.505 | 0.980 | 1.000 | 0.799..1.028 |
| H1 | nibble_popcount | 0.606 | 0.607 | 0.617 | 1.001 | 1.017 | 0.985..1.030 |
| H1 | matrix_sum_4x8 | 0.524 | 0.524 | 0.524 | 1.000 | 1.000 | 1.000..1.012 |
| H1 | seed16_rounds20 | 12.517 | 12.515 | 12.517 | 1.000 | 1.000 | 0.999..1.014 |
| H1 | count_words | 21.774 | 21.337 | 21.449 | 0.980 | 0.985 | 0.957..1.015 |
| H1 | scale_sample | 1.147 | 1.147 | 1.147 | 1.000 | 1.000 | 0.971..1.030 |
| H1 | remaining_budget | 5.760 | 5.522 | 5.409 | 0.959 | 0.939 | 0.914..0.968 |
| H1 | read_u32_le | 1.186 | 1.189 | 1.325 | 1.002 | 1.117 | 1.075..1.147 |
| H2 | mix64 | 0.738 | 0.738 | 0.738 | 1.000 | 1.000 | 0.971..1.030 |
