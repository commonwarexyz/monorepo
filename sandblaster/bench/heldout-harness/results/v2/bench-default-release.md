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
| H1v2 | v2_parse_u32 | 3.086 | 3.112 | 3.345 | 1.008 | 1.084 | 1.078..1.087 |
| H1v2 | v2_hex_encode_lower | 22.425 | 22.654 | 22.491 | 1.010 | 1.003 | 0.996..1.014 |
| H1v2 | v2_hex_decode | 10.223 | 10.429 | 10.059 | 1.020 | 0.984 | 0.963..1.013 |
| H1v2 | v2_adler32 | 55.664 | 55.298 | 55.705 | 0.993 | 1.001 | 0.991..1.004 |
| H1v2 | v2_fletcher16 | 56.895 | 56.814 | 56.946 | 0.999 | 1.001 | 0.999..1.002 |
| H1v2 | v2_luhn_valid | 5.620 | 5.114 | 5.716 | 0.910 | 1.017 | 1.002..1.032 |
| H1v2 | v2_manhattan | 0.717 | 0.716 | 0.716 | 0.999 | 0.999 | 0.990..1.000 |
| H1v2 | v2_rect_intersection_area | 1.312 | 1.285 | 1.302 | 0.980 | 0.992 | 0.992..0.994 |
| H1v2 | v2_polygon_twice_area | 10.029 | 10.043 | 11.430 | 1.001 | 1.140 | 1.123..1.160 |
| H1v2 | v2_is_leap_year | 0.957 | 0.952 | 0.957 | 0.995 | 1.000 | 0.999..1.000 |
| H1v2 | v2_days_in_month | 1.414 | 1.414 | 1.418 | 1.000 | 1.003 | 1.000..1.005 |
| H1v2 | v2_day_of_week | 1.388 | 1.382 | 1.406 | 0.995 | 1.013 | 1.013..1.036 |
| H1v2 | v2_day_of_year | 2.838 | 2.729 | 2.699 | 0.961 | 0.951 | 0.947..0.974 |
| H1v2 | v2_seconds_to_hms | 1.142 | 1.132 | 1.142 | 0.992 | 1.000 | 0.983..1.015 |
| H1v2 | v2_count_overlapping_pairs | 74.015 | 64.148 | 66.976 | 0.867 | 0.905 | 0.706..0.959 |
| H1v2 | v2_high_nibble_histogram | 15.305 | 14.966 | 17.769 | 0.978 | 1.161 | 1.014..1.166 |
| H1v2 | v2_argmax | 9.412 | 9.439 | 9.438 | 1.003 | 1.003 | 0.977..1.020 |
| H1v2 | v2_min_max | 3.511 | 3.503 | 3.435 | 0.998 | 0.978 | 0.968..0.990 |
| H1v2 | v2_prefix_sums | 20.172 | 19.760 | 19.847 | 0.980 | 0.984 | 0.952..1.038 |
| H1v2 | v2_range_sum | 0.730 | 0.729 | 0.730 | 1.000 | 1.001 | 0.994..1.019 |
| H1v2 | v2_has_pair_with_sum | 16.614 | 15.658 | 16.212 | 0.942 | 0.976 | 0.941..0.999 |
| H1v2 | v2_dedup_sorted | 12.761 | 12.769 | 12.817 | 1.001 | 1.004 | 1.003..1.012 |
| H1v2 | v2_lower_bound | 2.173 | 2.048 | 2.007 | 0.942 | 0.924 | 0.920..0.924 |
| H1v2 | v2_rgb565_pack | 0.500 | 0.500 | 0.500 | 0.999 | 1.000 | 0.987..1.004 |
| H1v2 | v2_rgb565_unpack | 0.721 | 0.721 | 0.721 | 1.000 | 1.000 | 0.989..1.001 |
| H1v2 | v2_gcd | 14.722 | 13.613 | 13.728 | 0.925 | 0.932 | 0.904..0.991 |
| H1v2 | v2_lcm | 5.388 | 5.388 | 5.422 | 1.000 | 1.006 | 1.000..1.012 |
| H1v2 | v2_max_subarray_sum | 7.909 | 7.988 | 7.848 | 1.010 | 0.992 | 0.986..0.995 |
| H1v2 | v2_brackets_balanced | 9.174 | 9.080 | 9.239 | 0.990 | 1.007 | 0.997..1.011 |
| H1v2 | v2_count_inversions | 220.418 | 262.939 | 263.265 | 1.193 | 1.194 | 1.046..1.244 |
