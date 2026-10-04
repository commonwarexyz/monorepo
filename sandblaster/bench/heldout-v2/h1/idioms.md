# h1v2 idioms (second blind held-out set)

Twenty-five everyday idioms, disjoint from the first held-out set. Each maps to
one or two functions in `src/lib.rs`.

1. **Decimal parse with overflow** (parsing) — ASCII digits to `u32`, rejecting empty input, non-digits and overflow. `parse_u32`
2. **Hex encode / decode** (encoding) — bytes to lowercase hex and back, rejecting odd length and bad nibbles. `hex_encode_lower`, `hex_decode`
3. **Adler-32** (checksum) — two running sums modulo 65521 over a byte slice. `adler32`
4. **Fletcher-16** (checksum) — two running sums modulo 255. `fletcher16`
5. **Luhn check** (validation) — doubled alternate digits over an ASCII digit string, read right to left. `luhn_valid`
6. **Manhattan distance** (integer geometry, straight-line) — sum of absolute coordinate differences. `manhattan`
7. **Rectangle intersection area** (integer geometry, straight-line) — overlap of two half-open axis-aligned rectangles. `rect_intersection_area`
8. **Shoelace area** (integer geometry, loop with wraparound index, can overflow) — twice the signed polygon area. `polygon_twice_area`
9. **Leap year and month length** (date arithmetic, straight-line). `is_leap_year`, `days_in_month`
10. **Day of week** (date arithmetic, small table + straight-line) — Sakamoto's method. `day_of_week`
11. **Day of year** (date arithmetic, loop over months). `day_of_year`
12. **Seconds to h:m:s** (scheduling arithmetic, straight-line div/mod). `seconds_to_hms`
13. **Overlapping interval pairs** (scheduling, nested loops) — count pairs of half-open intervals that overlap. `count_overlapping_pairs`
14. **Bucketed histogram** (histogram) — count bytes by high nibble into 16 buckets. `high_nibble_histogram`
15. **Argmax** (small search) — index of the first maximum, `None` on empty. `argmax`
16. **Min and max in one pass** (min/max). `min_max`
17. **Prefix sums and range query** (prefix sums, indexing can panic). `prefix_sums`, `range_sum`
18. **Pair with target sum** (two-pointer while loop over a sorted slice). `has_pair_with_sum`
19. **Dedup sorted in place** (two-pointer, mutating a slice). `dedup_sorted`
20. **Lower bound** (binary search while loop). `lower_bound`
21. **RGB565 bit fields** (bit fields, straight-line pack/unpack). `rgb565_pack`, `rgb565_unpack`
22. **GCD and LCM** (Euclid while loop; LCM can panic on overflow). `gcd`, `lcm`
23. **Maximum subarray** (Kadane, loop with running state, can overflow). `max_subarray_sum`
24. **Balanced brackets** (validation with an explicit stack). `brackets_balanced`
25. **Inversion count** (naive nested loops over a slice). `count_inversions`
