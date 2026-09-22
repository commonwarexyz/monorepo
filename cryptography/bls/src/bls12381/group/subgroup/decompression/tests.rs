use super::*;
use commonware_utils::{ScriptedRng, TestRng};
use num_bigint::BigUint;
use rand_core::Rng;
use std::collections::HashSet;

pub(super) fn fixtures(n: usize) -> Vec<Affine> {
    let mut rng = TestRng::new(0);
    let mut distinct = HashSet::new();
    (0..n)
        .map(|_| {
            loop {
                let mut scalar = [0; 32];
                rng.fill_bytes(&mut scalar);
                let Ok(secret) = blst::min_pk::SecretKey::from_bytes(&scalar) else {
                    continue;
                };
                let public = secret.sk_to_pk();
                if !distinct.insert(public.to_bytes()) {
                    continue;
                }
                let bytes = public.serialize();
                break Affine {
                    x: read_field(bytes[..48].try_into().unwrap()).unwrap(),
                    y: read_field(bytes[48..].try_into().unwrap()).unwrap(),
                };
            }
        })
        .collect()
}

// Fixtures, including full-curve negative-test points, stay private to tests.
pub(super) fn public_points(points: &[Affine]) -> Vec<G1> {
    points
        .iter()
        .map(|p| G1::from_affine(p.x.into(), p.y.into()))
        .collect()
}

fn affine(point: G1) -> Affine {
    let (x, y) = point.to_affine().unwrap();
    Affine {
        x: x.into(),
        y: y.into(),
    }
}

pub(super) fn encode(points: &[Affine], format: Format) -> Vec<u8> {
    struct Encode<'a>(&'a [Affine], Format);
    impl WithBackend for Encode<'_> {
        type Output = Vec<u8>;
        #[inline(always)]
        fn call<B: Backend>(self, backend: B) -> Self::Output {
            let a = Arithmetic::<B> {
                ring: Ring::new(backend),
                roots: RootWidth::Four,
            };
            match self.1 {
                Format::Standard => self
                    .0
                    .iter()
                    .flat_map(|point| a.encode_standard(point))
                    .collect(),
                Format::Pair => a.encode_pairs(self.0),
                Format::Triple => a.encode_triples(self.0),
            }
        }
    }
    with_backend(Encode(points, format))
}

fn receive(bytes: &[u8], format: Format, rng: &mut impl CryptoRng) -> Option<Vec<G1>> {
    Receive {
        bytes,
        format,
        roots: RootWidth::Four,
        rng,
    }
    .run()
}

#[test]
fn exponent_and_batched_roots() {
    let p = BigUint::parse_bytes(b"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16).unwrap();
    let exponent = SIXTH_ROOT
        .iter()
        .fold(BigUint::from(0u8), |e, &(s, p)| (e << s) + p);
    assert_eq!(exponent * 108u8, &p + 17u8);
    assert_eq!(
        BigUint::from_bytes_be(&ROOT_NINE.to_bytes()),
        BigUint::from(2u8).modpow(&((&p - 1u8) / 9u8), &p)
    );
    struct Roots;
    impl WithBackend for Roots {
        type Output = ();
        #[inline(always)]
        fn call<B: Backend>(self, backend: B) {
            let a = Arithmetic::<B> {
                ring: Ring::new(backend),
                roots: RootWidth::Four,
            };
            let inputs: [_; 8] =
                core::array::from_fn(|i| a.cube(&a.fp_sqr(&Fp::from_u64(i as u64 + 1).into())));
            let roots = extract_roots::<8>(&inputs).unwrap();
            for (input, root) in inputs.iter().zip(roots) {
                assert!(a.fp_eq(&a.cube(&a.fp_sqr(&root)), input));
                assert!(a.fp_eq(&root, &extract_roots::<1>(&[*input]).unwrap()[0]));
            }
            let ninth: Field = ROOT_NINE.into();
            let inverse = a.ring.invert(ninth).unwrap();
            assert!(a.fp_eq(&a.fp_mul(&ninth, &inverse), &Field::ONE));
            assert!(extract_roots::<1>(&[Field::ONE]).is_some());
            assert!(extract_roots::<2>(&[ninth, inverse]).is_none());
            for lane in 0..4 {
                for invalid in [Field::ZERO, ninth, a.fp_neg(&Field::ONE)] {
                    let mut values = [Field::ONE; 4];
                    values[lane] = invalid;
                    assert!(extract_roots::<4>(&values).is_none());
                }
            }
        }
    }
    with_backend(Roots);
}

#[test]
fn receiver_preserves_points_and_checks_subgroups() {
    let mut points = fixtures(97);
    points[1] = points[0];
    points[4].y = Fp::from(points[3].y).neg().into();
    points[4].x = points[3].x;
    for format in [Format::Standard, Format::Pair, Format::Triple] {
        for len in [0, 1, 2, 3, 4, 11, 12, 13, 81, 82, 97] {
            let bytes = encode(&points[..len], format);
            assert_eq!(bytes.len(), 48 * len);
            assert_eq!(
                receive(&bytes, format, &mut TestRng::new(1)).unwrap(),
                public_points(&points[..len])
            );
            if !bytes.is_empty() {
                assert!(
                    receive(&bytes[..bytes.len() - 1], format, &mut ScriptedRng::new([])).is_none()
                );
            }
        }
        // Malformation at the end of a batch must fail before drawing randomness.
        let mut bytes = encode(&points, format);
        *bytes.last_mut().unwrap() ^= 1;
        bytes[48 * 96] = 0xff;
        assert!(receive(&bytes, format, &mut ScriptedRng::new([])).is_none());
    }
    let order_three = G1::from_affine(Fp::ZERO, Fp::from_u64(2));
    let order_eleven = {
        let mut bytes = [0; 48];
        for (word, chunk) in [
            0x19b3e2c8c6bbf59du64,
            0x3c326b531fc1e639,
            0xd29200c28624ac60,
            0x4f251a12908c9b7f,
            0x735318617f625954,
            0xcc71cdf03229b1ef,
        ]
        .iter()
        .zip(bytes.chunks_exact_mut(8))
        {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        bytes[0] |= 0x80;
        let p = G1::on_curve(&bytes).unwrap();
        G1::from_affine(p.x.into(), p.y.into())
    };
    for torsion in [order_three, order_eleven] {
        assert!(G1::from_bytes(&torsion.to_bytes()).is_none());
        for index in [0, 1, 2, 95, 96] {
            let mut bad = points.clone();
            bad[index] = affine(public_points(&bad[index..index + 1])[0].add(&torsion));
            for format in [Format::Standard, Format::Pair, Format::Triple] {
                let bytes = encode(&bad, format);
                assert!(receive(&bytes, format, &mut TestRng::new(2)).is_none());
            }
        }
    }
}

#[test]
fn exceptional_fibers_and_canonical_mutations() {
    struct Exceptional(Vec<Affine>);
    impl WithBackend for Exceptional {
        type Output = ();
        #[inline(always)]
        fn call<B: Backend>(self, backend: B) {
            let a = Arithmetic::<B> {
                ring: Ring::new(backend),
                roots: RootWidth::Four,
            };
            let base = self.0[0];
            for i in 0..64u64 {
                let mut point = base;
                if i != 0 {
                    point.x = a.fp_add(&point.x, &Fp::from_u64(i).into());
                }
                let triples = [base, point, base];
                assert_eq!(
                    a.valid_points(&triples),
                    triples.iter().all(|p| a.valid_affine(p))
                );
            }
            for point in [
                Affine::ZERO,
                Affine {
                    x: Field::ZERO,
                    y: Fp::from_u64(2).into(),
                },
            ] {
                assert!(!a.valid_points(&[base, point, base]));
            }
            let mut cases = vec![self.0];
            for x in a.roots(base.x) {
                for y in [base.y, a.fp_neg(&base.y)] {
                    let triple = vec![base, Affine { x, y }, base];
                    assert_eq!(a.encode_triples(&triple)[48] & 0x80, 0x80);
                    cases.push(triple);
                }
            }
            // Non-orbit exceptional fiber: t=5, y0=22, y1=14/5.
            let t = Fp::from_u64(5).into();
            let y0 = Fp::from_u64(22).into();
            let y1 = a.fp_mul(&Fp::from_u64(14).into(), &a.ring.invert(t).unwrap());
            let b = a.fp_sub(&a.fp_sqr(&y1), &a.four());
            let mut x1 = extract_roots::<1>(&[a.fp_sqr(&b)]).unwrap()[0];
            if !a.fp_eq(&a.cube(&x1), &b) {
                x1 = a.fp_neg(&x1);
            }
            for negative in [false, true] {
                let triple = vec![
                    Affine {
                        x: a.fp_mul(&t, &x1),
                        y: if negative { a.fp_neg(&y0) } else { y0 },
                    },
                    Affine {
                        x: x1,
                        y: if negative { a.fp_neg(&y1) } else { y1 },
                    },
                    base,
                ];
                assert!(triple.iter().all(|point| a.valid_affine(point)));
                assert_eq!(a.encode_triples(&triple)[48] & 0x80, 0x80);
                cases.push(triple);
            }
            for points in &cases {
                for format in [Format::Pair, Format::Triple] {
                    let bytes = match format {
                        Format::Pair => a.encode_pairs(points),
                        _ => a.encode_triples(points),
                    };
                    let decoded = match format {
                        Format::Pair => a.decode_pairs(&bytes),
                        _ => a.decode_triples(&bytes),
                    }
                    .unwrap();
                    assert_eq!(public_points(&decoded), public_points(points));
                }
            }
            let mut rng = TestRng::new(7);
            for points in &cases[..2] {
                for format in [Format::Pair, Format::Triple] {
                    let bytes = match format {
                        Format::Pair => a.encode_pairs(points),
                        _ => a.encode_triples(points),
                    };
                    for _ in 0..64 {
                        let mut changed = bytes.clone();
                        let offset = rng.next_u32() as usize % changed.len();
                        changed[offset] ^= 1 << (rng.next_u32() % 8);
                        let result = match format {
                            Format::Pair => a.decode_pairs(&changed),
                            _ => a.decode_triples(&changed),
                        };
                        if let Some(points) = result {
                            assert!(points.iter().all(|p| a.valid_affine(p)));
                            let canonical = match format {
                                Format::Pair => a.encode_pairs(&points),
                                _ => a.encode_triples(&points),
                            };
                            assert_eq!(changed, canonical);
                        }
                    }
                }
            }
            // Generic triples cannot alias a same-orbit fallback.
            let six = Fp::from_u64(6).into();
            let left = a.fp_mul(&six, &a.ring.invert(base.y).unwrap());
            let right = a.fp_mul(&base.y, &a.ring.invert(six).unwrap());
            let mut alias = Vec::from(field_bytes(&a.fp_sub(&left, &right)));
            alias.extend(field_bytes(&a.fp_add(&left, &right)));
            alias.extend(field_bytes(&base.x));
            assert!(a.decode_triples(&alias).is_none());
            let mut false_fallback = a.encode_pairs(&cases[0][..2]);
            false_fallback[48] |= 0x80;
            false_fallback.extend(a.encode_standard(&base));
            assert!(a.decode_triples(&false_fallback).is_none());
            for format in [Format::Pair, Format::Triple] {
                let bytes = match format {
                    Format::Pair => a.encode_pairs(&cases[0]),
                    _ => a.encode_triples(&cases[0]),
                };
                for offset in (0..bytes.len()).step_by(48) {
                    let mut changed = bytes.clone();
                    changed[offset..offset + 48].fill(0xff);
                    assert!(
                        match format {
                            Format::Pair => a.decode_pairs(&changed),
                            _ => a.decode_triples(&changed),
                        }
                        .is_none()
                    );
                }
                let modulus = commonware_formatting::from_hex(
                    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
                ).unwrap();
                for offset in (0..bytes.len()).step_by(48) {
                    let mut changed = bytes.clone();
                    let flags = changed[offset] & 0xe0;
                    changed[offset..offset + 48].copy_from_slice(&modulus);
                    changed[offset] |= flags;
                    assert!(
                        match format {
                            Format::Pair => a.decode_pairs(&changed),
                            _ => a.decode_triples(&changed),
                        }
                        .is_none()
                    );
                }
                let mut infinity = [0; 48];
                infinity[0] = 0xc0;
                assert!(a.decode_pairs(&infinity).is_none());
                assert!(a.decode_triples(&infinity).is_none());
            }
        }
    }
    with_backend(Exceptional(fixtures(6)));
}

#[test]
#[ignore = "manual complete graph receiver check with distinct points"]
fn large_receiver_uses_certified_subgroup_check() {
    let mut points = fixtures(100_000);
    let bytes = encode(&points, Format::Triple);
    assert_eq!(
        receive(&bytes, Format::Triple, &mut TestRng::new(10)).unwrap(),
        public_points(&points)
    );
    let torsion = G1::from_affine(Fp::ZERO, Fp::from_u64(2));
    let last = points.last_mut().unwrap();
    *last = affine(G1::from_affine(last.x.into(), last.y.into()).add(&torsion));
    assert!(
        receive(
            &encode(&points, Format::Triple),
            Format::Triple,
            &mut TestRng::new(11)
        )
        .is_none()
    );
}

#[test]
fn joint_wire_vectors_match_blst_research() {
    let generator = G1::generator();
    let mut point = generator;
    let points: Vec<_> = (0..7)
        .map(|_| {
            let result = affine(point);
            point = point.add(&generator);
            result
        })
        .collect();
    for (format, hex) in [
        (Format::Pair, include_str!("pair.hex")),
        (Format::Triple, include_str!("triple.hex")),
    ] {
        let bytes = commonware_formatting::from_hex(hex.trim()).unwrap();
        assert_eq!(encode(&points, format), bytes);
        assert_eq!(
            receive(&bytes, format, &mut TestRng::new(0)).unwrap(),
            public_points(&points)
        );
    }
}
