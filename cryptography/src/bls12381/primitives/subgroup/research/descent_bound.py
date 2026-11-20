"""Arithmetic diagnostics for the rational 3-torsion descent map; not a verifier."""

from math import gcd


def add(p, left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    xx, yy = right
    if x == xx and (y+yy) % p == 0:
        return None
    if x == xx:
        slope = 3*x*x*pow(2*y, -1, p) % p
    else:
        slope = (yy-y)*pow(xx-x, -1, p) % p
    xxx = (slope*slope-x-xx) % p
    return xxx, (slope*(x-xxx)-y) % p


def mul(p, n, point):
    answer = None
    while n:
        if n & 1:
            answer = add(p, answer, point)
        point = add(p, point, point)
        n >>= 1
    return answer


def representative(p, point):
    if point is None:
        return 1
    _, y = point
    # 16 and 1/4 are identical modulo cubes, because their quotient is 4^3.
    return 16 % p if y == 2 else (y-2) % p


def character(p, point):
    return pow(representative(p, point), (p-1)//3, p)


def verify():
    for p in (7, 13, 19, 31, 37, 43, 61, 67, 73, 97):
        points = [None]+[(x, y) for x in range(p) for y in range(p)
                         if (y*y-x*x*x-4) % p == 0]
        for left in points:
            for right in points:
                assert character(p, add(p, left, right)) == character(p, left)*character(p, right) % p
        values = {character(p, point) for point in points}
        kernel = {point for point in points if character(p, point) == 1}
        triples = {mul(p, 3, point) for point in points}
        assert triples <= kernel
        if len(points) % 9:
            assert triples == kernel
        print(f"p={p} #E={len(points)} image={len(values)} kernel={len(kernel)} [3]E={len(triples)}")

    x = -0xd201000000010000
    r = x**4-x*x+1
    h = (x-1)**2//3
    p = (x-1)**2*r//3+x
    assert p == int('1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab', 16)
    assert h == 3*(11*10177*859267*52437899)**2
    assert (r*h) % 3 == 0 and (r*h) % 9 != 0
    assert p % 3 == 1
    torsion = (0, 2)
    assert mul(p, 3, torsion) is None
    zeta = character(p, torsion)
    assert zeta != 1 and pow(zeta, 3, p) == 1
    print(f"BLS p mod9={p%9}; chi(T)={zeta:#x}")
    print(f"remaining cofactor h/3={h//3}; gcd(h/3,p-1)={gcd(h//3,p-1)}")
    print(f"cofactor factors modp-1: {[(ell, (p-1)%ell) for ell in (11,10177,859267,52437899)]}")

    # Explicit residual-cofactor counterexample: [3]Q has trivial cubic character
    # but remains outside G1. The square root exists because p is 3 modulo 4.
    for xx in range(1, 100):
        yy = pow((xx**3+4)%p, (p+1)//4, p)
        if yy*yy % p != (xx**3+4)%p:
            continue
        point = (xx, yy)
        residual = mul(p, 3, point)
        if mul(p, r, residual) is not None:
            assert character(p, residual) == 1
            assert mul(p, r*h, point) is None
            for a in range(6):
                for b in range(6):
                    left, right = mul(p, a, point), mul(p, b, torsion)
                    assert character(p, add(p, left, right)) == character(p, left)*character(p, right)%p
            print(f"residual counterexample = [3]({xx}, sqrt({xx**3+4})); x={residual[0]:#x}; y={residual[1]:#x}")
            eleven = mul(p, r*h//(11*11), point)
            if mul(p, 11, eleven) is not None:
                eleven = mul(p, 11, eleven)
            assert eleven is not None and mul(p, 11, eleven) is None
            assert character(p, eleven) == 1
            assert mul(p, r, eleven) is not None
            print(f"order11 counterexample: x={eleven[0]:#x}; y={eleven[1]:#x}")
            break
    else:
        raise AssertionError("residual counterexample not found")

    # Eight equal order11 points on an eight-cycle. Each edge has an independent
    # sign at each endpoint, hence 16 sign bits; degree-two vertices force opposite
    # signs. Arithmetic mod11 exactly models their cyclic subgroup.
    accepted = 0
    for signs in range(1 << 16):
        sums = [0]*8
        for edge in range(8):
            for endpoint, vertex in enumerate((edge, (edge+1)%8)):
                sums[vertex] += 1 if signs & (1 << (2*edge+endpoint)) else -1
        accepted += all(value % 11 == 0 for value in sums)
    assert accepted == 256
    print(f"order11 eight-cycle accepts {accepted}/65536 endpoint-sign assignments; exactly 1/256")


if __name__ == "__main__":
    verify()
