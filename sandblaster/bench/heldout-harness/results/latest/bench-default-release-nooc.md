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
| H1 | decimal_digits | 8.498 | 3.358 | 3.414 | 0.395 | 0.402 | 0.375..0.407 |
| H1 | base32_encoded_len | 0.953 | 1.187 | 0.953 | 1.246 | 1.000 | 0.964..1.005 |
| H1 | base64_encoded_len | 1.241 | 1.243 | 1.238 | 1.001 | 0.998 | 0.993..1.029 |
| H1 | reverse_bits | 0.502 | 0.503 | 0.505 | 1.001 | 1.006 | 0.995..1.021 |
| H1 | gray_encode | 0.500 | 0.504 | 0.499 | 1.008 | 0.998 | 0.983..1.037 |
| H1 | gray_decode | 6.905 | 5.178 | 5.124 | 0.750 | 0.742 | 0.740..0.763 |
| H1 | next_power_of_two | 0.947 | 1.125 | 0.929 | 1.188 | 0.980 | 0.977..0.986 |
| H1 | isqrt | 35.487 | 36.860 | 35.670 | 1.039 | 1.005 | 0.979..1.015 |
| H1 | fenwick_prefix_sum | 1.887 | 1.862 | 1.858 | 0.987 | 0.985 | 0.982..0.988 |
| H1 | buddy_order | 4.269 | 4.237 | 4.497 | 0.993 | 1.053 | 1.027..1.079 |
| H1 | binomial_meld_carries | 27.639 | 28.163 | 28.310 | 1.019 | 1.024 | 0.993..1.058 |
| H1 | hamming_distance | 3.583 | 3.569 | 3.565 | 0.996 | 0.995 | 0.989..0.999 |
| H1 | run_count | 6.709 | 7.065 | 6.709 | 1.053 | 1.000 | 0.982..1.020 |
| H1 | first_newline | 5.658 | 5.756 | 5.652 | 1.017 | 0.999 | 0.999..1.003 |
| H1 | first_printable | 2.230 | 2.259 | 2.197 | 1.013 | 0.985 | 0.974..0.997 |
| H1 | checked_sum | 6.035 | 5.491 | 5.558 | 0.910 | 0.921 | 0.908..0.928 |
| H1 | ring_index | 0.650 | 0.675 | 0.692 | 1.038 | 1.065 | 0.989..1.141 |
| H1 | align_up | 0.490 | 0.490 | 0.490 | 1.000 | 1.000 | 0.999..1.000 |
| H1 | ceil_div | 0.511 | 0.511 | 0.738 | 1.000 | 1.445 | 1.407..1.519 |
| H1 | crc8 | 21.436 | 21.365 | 21.459 | 0.997 | 1.001 | 0.999..1.003 |
| H1 | parity | 3.179 | 3.251 | 3.236 | 1.023 | 1.018 | 0.985..1.044 |
| H1 | trailing_ones | 1.749 | 1.738 | 1.795 | 0.994 | 1.027 | 1.021..1.031 |
| H1 | byte_swap | 0.951 | 0.488 | 0.488 | 0.513 | 0.513 | 0.513..0.513 |
| H1 | nibble_popcount | 0.606 | 0.597 | 0.596 | 0.985 | 0.984 | 0.962..1.003 |
| H1 | matrix_sum_4x8 | 0.498 | 0.493 | 0.493 | 0.989 | 0.990 | 0.969..1.003 |
| H1 | seed16_rounds20 | 12.302 | 12.292 | 12.299 | 0.999 | 1.000 | 0.984..1.017 |
| H1 | count_words | 18.400 | 19.768 | 18.069 | 1.074 | 0.982 | 0.972..1.006 |
| H1 | scale_sample | 1.093 | 1.216 | 1.092 | 1.112 | 0.999 | 0.946..1.019 |
| H1 | remaining_budget | 5.798 | 5.089 | 5.220 | 0.878 | 0.900 | 0.893..0.905 |
| H1 | read_u32_le | 1.155 | 1.175 | 1.237 | 1.017 | 1.071 | 1.063..1.111 |
| H2 | mix64 | 0.715 | 0.715 | 0.721 | 1.000 | 1.007 | 0.992..1.032 |
