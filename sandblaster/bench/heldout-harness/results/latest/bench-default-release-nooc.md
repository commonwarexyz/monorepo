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
| H1 | decimal_digits | 3.528 | 3.371 | 3.616 | 0.955 | 1.025 | 0.999..1.060 |
| H1 | base32_encoded_len | 0.942 | 0.942 | 0.942 | 1.000 | 1.000 | 1.000..1.000 |
| H1 | base64_encoded_len | 1.234 | 1.234 | 1.227 | 1.000 | 0.995 | 0.989..1.010 |
| H1 | reverse_bits | 0.483 | 0.483 | 0.483 | 1.000 | 1.000 | 0.998..1.003 |
| H1 | gray_encode | 0.484 | 0.485 | 0.484 | 1.001 | 1.000 | 0.990..1.005 |
| H1 | gray_decode | 5.086 | 5.163 | 5.746 | 1.015 | 1.130 | 1.095..1.136 |
| H1 | next_power_of_two | 0.925 | 0.925 | 1.038 | 1.000 | 1.122 | 1.114..1.132 |
| H1 | isqrt | 35.110 | 33.976 | 37.415 | 0.968 | 1.066 | 1.041..1.075 |
| H1 | fenwick_prefix_sum | 2.215 | 1.871 | 1.863 | 0.845 | 0.841 | 0.757..0.850 |
| H1 | buddy_order | 4.094 | 4.071 | 4.401 | 0.994 | 1.075 | 1.052..1.089 |
| H1 | binomial_meld_carries | 27.893 | 27.395 | 27.323 | 0.982 | 0.980 | 0.972..0.987 |
| H1 | hamming_distance | 3.592 | 3.615 | 3.611 | 1.007 | 1.005 | 0.939..1.062 |
| H1 | run_count | 6.630 | 6.559 | 6.650 | 0.989 | 1.003 | 0.986..1.020 |
| H1 | first_newline | 5.720 | 5.932 | 5.476 | 1.037 | 0.957 | 0.878..1.018 |
| H1 | first_printable | 2.076 | 2.019 | 2.048 | 0.973 | 0.986 | 0.935..1.003 |
| H1 | checked_sum | 5.239 | 5.561 | 5.246 | 1.062 | 1.001 | 0.991..1.016 |
| H1 | ring_index | 0.714 | 0.622 | 0.623 | 0.870 | 0.872 | 0.869..1.003 |
| H1 | align_up | 0.485 | 0.485 | 0.485 | 1.000 | 1.000 | 0.992..1.003 |
| H1 | ceil_div | 0.707 | 0.707 | 0.489 | 1.000 | 0.692 | 0.688..1.008 |
| H1 | crc8 | 21.746 | 21.472 | 21.487 | 0.987 | 0.988 | 0.983..0.999 |
| H1 | parity | 3.129 | 3.231 | 3.143 | 1.033 | 1.004 | 1.001..1.013 |
| H1 | trailing_ones | 1.719 | 1.736 | 1.716 | 1.010 | 0.998 | 0.968..1.006 |
| H1 | byte_swap | 0.483 | 0.483 | 0.483 | 1.000 | 1.000 | 0.996..1.013 |
| H1 | nibble_popcount | 0.585 | 0.586 | 0.585 | 1.002 | 1.000 | 0.985..1.007 |
| H1 | matrix_sum_4x8 | 0.487 | 0.487 | 0.488 | 1.000 | 1.000 | 0.994..1.010 |
| H1 | seed16_rounds20 | 11.988 | 11.991 | 11.993 | 1.000 | 1.000 | 0.997..1.005 |
| H1 | count_words | 18.079 | 18.463 | 17.779 | 1.021 | 0.983 | 0.972..0.995 |
| H1 | scale_sample | 1.069 | 1.069 | 1.069 | 1.000 | 1.000 | 0.995..1.008 |
| H1 | remaining_budget | 7.618 | 7.062 | 6.490 | 0.927 | 0.852 | 0.838..0.862 |
| H1 | read_u32_le | 1.139 | 1.145 | 1.145 | 1.005 | 1.005 | 0.996..1.011 |
| H2 | mix64 | 0.714 | 0.715 | 0.715 | 1.002 | 1.002 | 0.995..1.020 |
