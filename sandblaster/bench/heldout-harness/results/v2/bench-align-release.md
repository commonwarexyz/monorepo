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
| H1v2 | v2_parse_u32 | 3.115 | 3.105 | 3.107 | 0.997 | 0.998 | 0.993..1.015 |
| H1v2 | v2_hex_encode_lower | 22.812 | 22.542 | 22.715 | 0.988 | 0.996 | 0.992..0.998 |
| H1v2 | v2_hex_decode | 9.961 | 9.936 | 9.916 | 0.997 | 0.995 | 0.994..1.006 |
| H1v2 | v2_adler32 | 55.328 | 55.216 | 55.227 | 0.998 | 0.998 | 0.997..1.004 |
| H1v2 | v2_fletcher16 | 57.058 | 56.997 | 57.058 | 0.999 | 1.000 | 0.998..1.004 |
| H1v2 | v2_luhn_valid | 5.073 | 5.070 | 5.064 | 0.999 | 0.998 | 0.993..1.002 |
| H1v2 | v2_manhattan | 0.716 | 0.716 | 0.716 | 1.000 | 1.000 | 1.000..1.007 |
| H1v2 | v2_rect_intersection_area | 1.347 | 1.347 | 1.331 | 1.000 | 0.988 | 0.988..1.006 |
| H1v2 | v2_polygon_twice_area | 10.635 | 10.634 | 10.662 | 1.000 | 1.003 | 0.977..1.033 |
| H1v2 | v2_is_leap_year | 0.957 | 0.955 | 0.955 | 0.998 | 0.998 | 0.977..1.022 |
| H1v2 | v2_days_in_month | 1.156 | 1.212 | 1.153 | 1.049 | 0.998 | 0.976..1.015 |
| H1v2 | v2_day_of_week | 1.393 | 1.391 | 1.388 | 0.999 | 0.997 | 0.994..1.002 |
| H1v2 | v2_day_of_year | 2.836 | 2.795 | 2.817 | 0.986 | 0.993 | 0.978..1.009 |
| H1v2 | v2_seconds_to_hms | 1.139 | 1.141 | 1.142 | 1.002 | 1.003 | 0.985..1.032 |
| H1v2 | v2_count_overlapping_pairs | 163.370 | 136.638 | 155.355 | 0.836 | 0.951 | 0.867..1.053 |
| H1v2 | v2_high_nibble_histogram | 18.046 | 15.622 | 17.665 | 0.866 | 0.979 | 0.974..0.993 |
| H1v2 | v2_argmax | 9.359 | 9.438 | 9.510 | 1.008 | 1.016 | 1.016..1.017 |
| H1v2 | v2_min_max | 3.496 | 3.494 | 3.496 | 1.000 | 1.000 | 0.995..1.001 |
| H1v2 | v2_prefix_sums | 20.788 | 23.061 | 22.420 | 1.109 | 1.079 | 1.064..1.089 |
| H1v2 | v2_range_sum | 0.731 | 0.730 | 0.733 | 0.999 | 1.002 | 0.989..1.034 |
| H1v2 | v2_has_pair_with_sum | 15.564 | 15.747 | 15.945 | 1.012 | 1.025 | 1.017..1.030 |
| H1v2 | v2_dedup_sorted | 13.016 | 12.812 | 12.840 | 0.984 | 0.987 | 0.984..0.996 |
| H1v2 | v2_lower_bound | 2.013 | 2.014 | 2.014 | 1.001 | 1.000 | 0.991..1.009 |
| H1v2 | v2_rgb565_pack | 0.516 | 0.507 | 0.514 | 0.983 | 0.998 | 0.972..1.005 |
| H1v2 | v2_rgb565_unpack | 0.721 | 0.721 | 0.721 | 1.000 | 1.000 | 0.989..1.015 |
| H1v2 | v2_gcd | 13.400 | 13.547 | 14.783 | 1.011 | 1.103 | 1.072..1.104 |
| H1v2 | v2_lcm | 5.467 | 5.388 | 5.457 | 0.986 | 0.998 | 0.998..1.006 |
| H1v2 | v2_max_subarray_sum | 7.896 | 7.886 | 7.922 | 0.999 | 1.003 | 1.000..1.005 |
| H1v2 | v2_brackets_balanced | 9.135 | 9.107 | 9.071 | 0.997 | 0.993 | 0.985..1.004 |
| H1v2 | v2_count_inversions | 354.084 | 331.137 | 348.713 | 0.935 | 0.985 | 0.938..1.064 |
