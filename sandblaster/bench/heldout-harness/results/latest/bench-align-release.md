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
| H1 | decimal_digits | 3.640 | 3.672 | 3.661 | 1.009 | 1.006 | 0.983..1.053 |
| H1 | base32_encoded_len | 1.083 | 1.215 | 1.108 | 1.122 | 1.023 | 1.001..1.120 |
| H1 | base64_encoded_len | 1.256 | 1.252 | 1.251 | 0.996 | 0.996 | 0.923..1.078 |
| H1 | reverse_bits | 0.483 | 0.484 | 0.483 | 1.000 | 1.000 | 0.995..1.005 |
| H1 | gray_encode | 0.484 | 0.484 | 0.484 | 1.000 | 1.000 | 0.996..1.003 |
| H1 | gray_decode | 4.946 | 4.958 | 5.117 | 1.003 | 1.035 | 0.958..1.061 |
| H1 | next_power_of_two | 0.932 | 0.932 | 0.931 | 1.000 | 0.999 | 0.990..1.004 |
| H1 | isqrt | 22.680 | 22.814 | 22.631 | 1.006 | 0.998 | 0.994..1.009 |
| H1 | fenwick_prefix_sum | 1.876 | 1.881 | 1.877 | 1.003 | 1.001 | 0.985..1.024 |
| H1 | buddy_order | 4.251 | 4.150 | 4.159 | 0.976 | 0.978 | 0.952..1.051 |
| H1 | binomial_meld_carries | 28.412 | 29.205 | 32.949 | 1.028 | 1.160 | 0.883..1.227 |
| H1 | hamming_distance | 12.782 | 12.390 | 12.248 | 0.969 | 0.958 | 0.944..0.962 |
| H1 | run_count | 20.599 | 20.602 | 20.734 | 1.000 | 1.007 | 0.995..1.192 |
| H1 | first_newline | 5.516 | 5.463 | 5.416 | 0.990 | 0.982 | 0.956..1.024 |
| H1 | first_printable | 1.994 | 1.992 | 1.976 | 0.999 | 0.991 | 0.981..1.012 |
| H1 | checked_sum | 5.266 | 5.262 | 5.269 | 0.999 | 1.001 | 0.969..1.017 |
| H1 | ring_index | 0.752 | 0.751 | 0.752 | 0.998 | 1.000 | 0.984..1.010 |
| H1 | align_up | 0.713 | 0.712 | 0.714 | 0.999 | 1.002 | 0.993..1.009 |
| H1 | ceil_div | 0.803 | 0.806 | 0.804 | 1.003 | 1.001 | 0.976..1.018 |
| H1 | crc8 | 21.563 | 21.558 | 21.558 | 1.000 | 1.000 | 0.995..1.011 |
| H1 | parity | 3.126 | 3.122 | 3.129 | 0.999 | 1.001 | 0.990..1.008 |
| H1 | trailing_ones | 1.761 | 1.765 | 1.787 | 1.002 | 1.015 | 0.970..1.202 |
| H1 | byte_swap | 0.484 | 0.485 | 0.486 | 1.003 | 1.004 | 0.990..1.028 |
| H1 | nibble_popcount | 0.579 | 0.579 | 0.579 | 0.999 | 1.000 | 0.992..1.006 |
| H1 | matrix_sum_4x8 | 0.485 | 0.485 | 0.485 | 1.000 | 1.000 | 0.999..1.007 |
| H1 | seed16_rounds20 | 12.058 | 12.118 | 12.093 | 1.005 | 1.003 | 0.986..1.016 |
| H1 | count_words | 20.437 | 19.882 | 19.880 | 0.973 | 0.973 | 0.879..1.014 |
| H1 | scale_sample | 1.065 | 1.064 | 1.067 | 0.999 | 1.001 | 0.992..1.014 |
| H1 | remaining_budget | 5.176 | 5.169 | 5.388 | 0.999 | 1.041 | 0.940..1.099 |
| H1 | read_u32_le | 1.141 | 1.141 | 1.143 | 1.000 | 1.002 | 0.992..1.015 |
| H2 | mix64 | 0.703 | 0.703 | 0.706 | 1.000 | 1.004 | 0.992..1.015 |
