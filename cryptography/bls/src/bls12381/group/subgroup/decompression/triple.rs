//! Three points per sixth root, using https://eprint.iacr.org/2021/1446.
//!
//! This is a test-only format, with the same 48 bytes per point.

use super::*;

impl<B: Backend> Arithmetic<B> {
    #[inline(always)]
    fn double(&self, a: &Field) -> Field {
        self.fp_add(a, a)
    }

    // Return the numerators of z0 and z1, and their common denominator.
    #[inline(always)]
    fn parameters(&self, pair: &[Affine]) -> (Field, Field, Field) {
        let [a, b] = pair else { unreachable!() };
        let xy = self.fp_mul(&a.x, &b.x);
        let cross = self.fp_sub(&self.fp_mul(&a.x, &b.y), &self.fp_mul(&a.y, &b.x));
        let z0 = self.fp_mul(
            &b.x,
            &self.fp_sub(
                &self.double(&self.fp_sub(
                    &self.fp_mul(&self.fp_sqr(&a.x), &b.y),
                    &self.fp_mul(&a.y, &self.fp_sqr(&b.x)),
                )),
                &self.fp_mul(&xy, &self.fp_sub(&a.y, &b.y)),
            ),
        );
        let z1 = self.fp_add(
            &self.fp_sub(
                &self.fp_mul(&self.cube(&a.x), &b.y),
                &self.fp_mul(&a.y, &self.cube(&b.x)),
            ),
            &self.double(&self.fp_mul(&xy, &cross)),
        );
        (z0, z1, self.fp_sub(&self.fp_sqr(&a.y), &self.fp_sqr(&b.y)))
    }

    #[inline(always)]
    fn exceptional(&self, pair: &[Affine]) -> bool {
        let (z0, _, denominator) = self.parameters(pair);
        self.fp_is_zero(&z0) || self.fp_is_zero(&denominator)
    }

    #[inline(always)]
    pub(super) fn encode_triples(&self, points: &[Affine]) -> Vec<u8> {
        let affine = points;
        assert!(affine.iter().all(|point| self.valid_affine(point)));
        let records: Vec<_> = affine
            .chunks_exact(3)
            .map(|triple| self.parameters(&triple[..2]))
            .collect();
        let mut inverses: Vec<_> = records
            .iter()
            .map(|(_, _, denominator)| {
                if self.fp_is_zero(denominator) {
                    Field::ONE
                } else {
                    *denominator
                }
            })
            .collect();
        self.batch_invert(&mut inverses, &mut Vec::new()).unwrap();
        let mut bytes = Vec::with_capacity(48 * points.len());
        for (index, ((&(z0, z1, denominator), inverse), triple)) in records
            .iter()
            .zip(&inverses)
            .zip(affine.chunks_exact(3))
            .enumerate()
        {
            if self.fp_is_zero(&z0) || self.fp_is_zero(&denominator) {
                // The pair format covers the exceptional fibers. Its second
                // field has two unused high bits; bit 7 marks this fallback.
                let mut fallback = self.encode_pairs(&points[3 * index..3 * index + 2]);
                fallback[48] |= 0x80;
                bytes.extend(fallback);
                bytes.extend(self.encode_standard(&points[3 * index + 2]));
                continue;
            }
            bytes.extend(field_bytes(&self.fp_mul(&z0, inverse)));
            bytes.extend(field_bytes(&self.fp_mul(&z1, inverse)));
            let mut candidates = self.roots(triple[1].x).map(|x| field_bytes(&x));
            candidates.sort_unstable();
            let rank = candidates
                .iter()
                .position(|x| *x == field_bytes(&triple[1].x))
                .unwrap();
            let negative = field_bytes(&triple[2].y) > field_bytes(&self.fp_neg(&triple[2].y));
            let mut x = field_bytes(&triple[2].x);
            x[0] |= ((2 * rank + usize::from(negative)) as u8) << 5;
            bytes.extend(x);
        }
        bytes.extend(self.encode_pairs(&points[points.len() / 3 * 3..]));
        bytes
    }

    #[inline(always)]
    pub(super) fn decode_triples(&self, bytes: &[u8]) -> Option<Vec<Affine>> {
        if !bytes.len().is_multiple_of(48) {
            return None;
        }
        let mut records = reserved(bytes.len() / 144)?;
        let mut inverses = reserved(bytes.len() / 144)?;
        let mut decoded = filled(bytes.len() / 48, Affine::ZERO)?;
        for (index, triple) in bytes.chunks_exact(144).enumerate() {
            if triple[48] & 0x80 != 0 {
                let mut pair: [u8; 96] = triple[..96].try_into().unwrap();
                pair[48] &= !0x80;
                let pair = self.decode_pairs(&pair)?;
                if !self.exceptional(&pair) {
                    return None;
                }
                decoded[index * 3..index * 3 + 2].copy_from_slice(&pair);
                decoded[index * 3 + 2] = self.decode_standard(&triple[96..])?;
                continue;
            }
            let z0 = read_field(triple[..48].try_into().unwrap())?;
            let z1 = read_field(triple[48..96].try_into().unwrap())?;
            let mut x: [u8; 48] = triple[96..].try_into().unwrap();
            let selector = x[0] >> 5;
            if selector >= 6 {
                return None;
            }
            x[0] &= 0x1f;
            let x = read_field(&x)?;
            let c = self.fp_sub(&self.fp_sqr(&z1), &self.four());
            let denominator = self.fp_mul(&self.fp_sqr(&z0), &c);
            if self.fp_is_zero(&denominator) || self.fp_is_zero(&x) {
                return None;
            }
            records.push((index, z0, z1, x, c, selector));
            inverses.push(denominator);
        }
        let mut scratch = Vec::new();
        self.batch_invert(&mut inverses, &mut scratch)?;
        let mut coordinates = reserved(records.len())?;
        let mut radicands = reserved(records.len())?;
        for (&(_, z0, z1, x, c, _), inverse) in records.iter().zip(&inverses) {
            // t = x0/x1 = (z1^2 - 4)/z0^2. One inverse gives both t and 1/t.
            let t = self.fp_mul(&self.fp_sqr(&c), inverse);
            let inverse_t = self.fp_mul(&self.fp_sqr(&self.fp_sqr(&z0)), inverse);
            let ring = &self.ring;
            let t_squared = self.fp_sqr(&t);
            // y0 = z1(1 + 2t) - z0(t^2 + 2t)
            // y1 = (z1 - 2z0) + (2z1 - z0)/t
            let [y0, y1] = ring.batch_reduce_expand(&[
                ring.ready::<800>(
                    ring.prep_left(z1) * ring.prep(Field::ONE + t.scale::<2>())
                        + ring.prep_left(z0) * ring.negate(ring.prep(t_squared + t.scale::<2>())),
                ),
                ring.ready::<800>(
                    ring.prep_left(z1 - z0.scale::<2>()) * Field::ONE
                        + ring.prep_left(z1.scale::<2>() - z0) * inverse_t,
                ),
            ]);
            let values = [x, y0, y1];
            let [x_squared, y0_squared, y1_squared] = self.products(&values, &values);
            // Same-orbit pairs have a unique encoding in the fallback format.
            if self.fp_eq(&y0_squared, &y1_squared) {
                return None;
            }
            let [a, b] = ring.batch_reduce_expand(&[
                ring.ready::<800>(
                    ring.prep_left(x_squared) * x + ring.prep_left(self.four()) * Field::ONE,
                ),
                ring.ready::<800>(ring.prep_left(y1_squared - self.four()) * Field::ONE),
            ]);
            let ab = self.fp_mul(&a, &b);
            if self.fp_is_zero(&ab) {
                return None;
            }
            coordinates.push((t, y0, y1, ab));
            // a^3 b^2 = a(ab)^2 reuses the coordinate-recovery product.
            radicands.push(self.fp_mul(&a, &self.fp_sqr(&ab)));
        }
        let extracted = self.root_batch(&radicands)?;
        inverses.clear();
        inverses.extend(
            coordinates
                .iter()
                .zip(&extracted)
                .map(|(&(_, _, _, ab), root)| self.fp_mul(&self.fp_sqr(root), &ab)),
        );
        self.batch_invert(&mut inverses, &mut scratch)?;
        for (((&(index, _, _, x2, _, selector), &(t, y0, y1, ab)), root), inverse) in records
            .iter()
            .zip(&coordinates)
            .zip(&extracted)
            .zip(&inverses)
        {
            // root^6 = a^3 b^2, x1 = ab/root^2, y2 = root^3/ab.
            let x1 = self.ranked_root(
                self.fp_mul(&self.fp_sqr(&ab), inverse),
                usize::from(selector / 2),
            );
            let mut y2 = self.fp_mul(
                &self.fp_mul(&self.fp_sqr(&self.fp_sqr(root)), root),
                inverse,
            );
            if Fp::from(y2).lexicographically_largest().unwrap_u8() != selector & 1 {
                y2 = self.fp_neg(&y2);
            }
            let triple = [
                Affine {
                    x: self.fp_mul(&t, &x1),
                    y: y0,
                },
                Affine { x: x1, y: y1 },
                Affine { x: x2, y: y2 },
            ];
            if !self.valid_points(&triple) {
                return None;
            }
            decoded[3 * index..3 * index + 3].copy_from_slice(&triple);
        }
        let tail = self.decode_pairs(bytes.chunks_exact(144).remainder())?;
        decoded[bytes.len() / 144 * 3..].copy_from_slice(&tail);
        Some(decoded)
    }
}
