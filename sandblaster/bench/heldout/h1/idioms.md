# Held-out set h1: idiom list

Fixed before any code was written (2026-10-02). Each idiom gets one or two
ordinary, idiomatic Rust functions in `src/lib.rs`.

1. decimal digit count / ilog10
2. base-32 and base-64 encoded length
3. bit reversal
4. Gray code and its inverse
5. next power of two
6. isqrt by bisection
7. Fenwick prefix-sum walk over u32 indices
8. buddy-allocator order for a size
9. binomial-heap carry count
10. Hamming distance over two byte slices
11. run-length count over a byte slice
12. position of the first newline
13. position of the first printable byte (>= 0x20)
14. checked sum of a slice with an overflow error
15. ring-buffer index wrap
16. align-up and ceiling division
17. bitwise CRC-8
18. parity
19. trailing ones
20. byte swap by loop
21. build a small table, then read one entry
22. fixed-trip loops with bounds 4, 8, 16 and 20
23. a small state machine over bytes (for example, counting words)
24. clamp and saturating arithmetic chains
25. a little-endian u32 read from a byte slice

Exclusions: no function restates code from commonware's codec varint, its
storage MMR/merkle/qmdb, sha256, reed-solomon or curve25519.
