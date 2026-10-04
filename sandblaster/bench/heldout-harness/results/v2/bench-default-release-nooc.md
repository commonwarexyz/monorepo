agree  H1v2 v2_parse_u32 (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_hex_encode_lower (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_hex_decode (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_adler32 (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_fletcher16 (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_luhn_valid (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_manhattan (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_rect_intersection_area (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_polygon_twice_area (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_is_leap_year (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_days_in_month (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_day_of_week (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_day_of_year (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_seconds_to_hms (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_count_overlapping_pairs (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_high_nibble_histogram (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_argmax (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_min_max (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_prefix_sums (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_range_sum (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_has_pair_with_sum (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_dedup_sorted (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_lower_bound (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_rgb565_pack (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_rgb565_unpack (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_gcd (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_lcm (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_max_subarray_sum (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_brackets_balanced (512 inputs: rustc, A/A and optimized)
agree  H1v2 v2_count_inversions (512 inputs: rustc, A/A and optimized)
| set | function | rustc ns | A/A ns | optimized ns | A/A / rustc | optimized / rustc | optimized / rustc, rounds p10..p90 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| H1v2 | v2_parse_u32 | 3.100 | 3.110 | 3.143 | 1.003 | 1.014 | 1.013..1.015 |
| H1v2 | v2_hex_encode_lower | 22.202 | 22.202 | 22.283 | 1.000 | 1.004 | 1.001..1.007 |
| H1v2 | v2_hex_decode | 10.354 | 9.969 | 10.335 | 0.963 | 0.998 | 0.980..1.023 |
| H1v2 | v2_adler32 | 55.674 | 55.389 | 55.379 | 0.995 | 0.995 | 0.994..0.995 |
| H1v2 | v2_fletcher16 | 56.478 | 56.946 | 56.732 | 1.008 | 1.005 | 1.004..1.006 |
| H1v2 | v2_luhn_valid | 4.634 | 4.620 | 4.600 | 0.997 | 0.993 | 0.992..0.993 |
| H1v2 | v2_manhattan | 0.492 | 0.492 | 0.497 | 1.000 | 1.010 | 0.979..1.018 |
| H1v2 | v2_rect_intersection_area | 0.877 | 0.888 | 0.885 | 1.012 | 1.009 | 0.978..1.013 |
| H1v2 | v2_polygon_twice_area | 6.382 | 6.345 | 6.346 | 0.994 | 0.994 | 0.984..1.013 |
| H1v2 | v2_is_leap_year | 0.956 | 0.954 | 0.952 | 0.998 | 0.996 | 0.995..1.000 |
| H1v2 | v2_days_in_month | 1.135 | 1.452 | 1.407 | 1.279 | 1.240 | 1.238..1.241 |
| H1v2 | v2_day_of_week | 0.981 | 0.963 | 0.973 | 0.982 | 0.992 | 0.965..1.053 |
| H1v2 | v2_day_of_year | 3.029 | 2.665 | 2.670 | 0.880 | 0.881 | 0.874..0.887 |
| H1v2 | v2_seconds_to_hms | 1.162 | 1.163 | 1.169 | 1.000 | 1.005 | 0.986..1.033 |
| H1v2 | v2_count_overlapping_pairs | 32.430 | 32.654 | 32.516 | 1.007 | 1.003 | 1.002..1.003 |
| H1v2 | v2_high_nibble_histogram | 12.937 | 12.947 | 12.919 | 1.001 | 0.999 | 0.994..1.003 |
| H1v2 | v2_argmax | 9.736 | 9.410 | 9.476 | 0.966 | 0.973 | 0.965..0.977 |
| H1v2 | v2_min_max | 3.499 | 3.489 | 3.506 | 0.997 | 1.002 | 0.975..1.016 |
| H1v2 | v2_prefix_sums | 18.590 | 18.845 | 18.789 | 1.014 | 1.011 | 0.966..1.164 |
| H1v2 | v2_range_sum | 0.742 | 0.745 | 0.745 | 1.005 | 1.004 | 0.982..1.019 |
| H1v2 | v2_has_pair_with_sum | 16.434 | 15.419 | 15.887 | 0.938 | 0.967 | 0.966..0.969 |
| H1v2 | v2_dedup_sorted | 13.074 | 12.861 | 12.960 | 0.984 | 0.991 | 0.990..0.992 |
| H1v2 | v2_lower_bound | 2.030 | 2.009 | 2.010 | 0.990 | 0.990 | 0.989..1.001 |
| H1v2 | v2_rgb565_pack | 0.498 | 0.500 | 0.498 | 1.003 | 1.000 | 0.995..1.005 |
| H1v2 | v2_rgb565_unpack | 0.721 | 0.721 | 0.721 | 1.000 | 1.000 | 0.999..1.001 |
| H1v2 | v2_gcd | 14.814 | 13.423 | 13.733 | 0.906 | 0.927 | 0.917..0.928 |
| H1v2 | v2_lcm | 5.404 | 5.456 | 5.390 | 1.010 | 0.997 | 0.990..1.003 |
| H1v2 | v2_max_subarray_sum | 5.711 | 5.566 | 5.782 | 0.975 | 1.013 | 0.976..1.036 |
| H1v2 | v2_brackets_balanced | 9.079 | 8.973 | 8.979 | 0.988 | 0.989 | 0.983..0.998 |
| H1v2 | v2_count_inversions | 51.677 | 51.514 | 51.626 | 0.997 | 0.999 | 0.998..1.010 |
