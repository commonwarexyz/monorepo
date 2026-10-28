//! Pointcheval-Sanders synchronized aggregate signatures (PS-SAS) over BLS12-381.
//!
//! This module implements the synchronized aggregate signature of Tezuka and Tanaka
//! ([arXiv:2304.00265](https://arxiv.org/abs/2304.00265)), generic over [`Variant`]: signatures
//! and period bases live in `V::Signature`, public keys in `V::Public`. The paper proves the
//! [`MinSig`](super::super::variant::MinSig) layout (signatures in G1, keys in G2);
//! [`MinPk`](super::super::variant::MinPk) swaps the groups.
//!
//! A private key is `(x, y)` and its public key is `(X, Y) = (x G, y G)`. Signing a message in a
//! period `t` computes `B = (x + c y) H1(t)` with `c = H2(t, m)`. Every signer in a period uses
//! the same base `H1(t)`, so signatures from distinct keys over distinct messages in one period
//! sum into an aggregate that verifies with one pairing product:
//!
//! ```text
//! e(sum_i X_i + c_i Y_i, H1(t)) = e(G, sum_i B_i)
//! ```
//!
//! # Security
//!
//! A key must sign at most one message per period. Two signatures from one key over different
//! messages in the same period reveal `x H1(t)` and `y H1(t)`, which lets anyone sign any message
//! for that key in that period. The scheme does not track periods; callers must.
//!
//! Security holds in the random oracle model under the interactive generalized
//! Pointcheval-Sanders assumption, for keys whose holders know their secrets (the certified-key
//! model). Verify a [`ProofOfKnowledge`] for every public key before aggregating over it.
//!
//! Period identifiers are hashed as given, so callers must encode them uniquely, including any
//! protocol domain.

use super::{
    super::{
        Error,
        group::{FixedBase, Private, Scalar, ScalarReadCfg, SmallScalar},
        variant::Variant,
    },
    batch::{bisect_ranges, random_scalars},
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use bytes::BufMut;
use commonware_codec::{Buf, Encode, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_math::algebra::{Additive, CryptoGroup, HashToGroup, Random, Space};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::union_unique;
use hashbrown::{HashMap, HashSet};
use rand_core::CryptoRng;

/// Domain separation tag for hashing a period to its signing base.
const PERIOD: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_SAS_PERIOD";

/// Domain separation tag for hashing a message to its scalar.
const MESSAGE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_SAS_MESSAGE";

/// Domain separation tag for the proof-of-knowledge challenge.
const PROOF: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_SAS_PROOF";

/// Minimum signers of one message in a batch before their `Y` terms are folded into one.
const FOLD_MIN: usize = 32;

/// A PS-SAS private key `(x, y)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKey {
    x: Private,
    y: Private,
}

impl PrivateKey {
    /// Creates a private key from its two secret scalars.
    pub const fn new(x: Private, y: Private) -> Self {
        Self { x, y }
    }
}

impl Random for PrivateKey {
    fn random(mut rng: impl CryptoRng) -> Self {
        Self::new(Private::random(&mut rng), Private::random(&mut rng))
    }
}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.x.write(buf);
        self.y.write(buf);
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self::new(Private::read(buf)?, Private::read(buf)?))
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = 2 * Private::SIZE;
}

/// A PS-SAS public key `(X, Y) = (x G, y G)` in `V::Public`.
///
/// Hashing uses a fingerprint of `X` computed once at construction. Hashing a group element
/// compresses it, and verification looks keys up on every batch.
#[derive(Debug)]
pub struct PublicKey<V: Variant> {
    x: V::Public,
    y: V::Public,
    fingerprint: u64,
}

impl<V: Variant> PartialEq for PublicKey<V> {
    fn eq(&self, other: &Self) -> bool {
        self.x == other.x && self.y == other.y
    }
}

impl<V: Variant> Eq for PublicKey<V> {}

impl<V: Variant> core::hash::Hash for PublicKey<V> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Equal keys have equal `X` and therefore equal fingerprints.
        state.write_u64(self.fingerprint);
    }
}

impl<V: Variant> Clone for PublicKey<V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V: Variant> Copy for PublicKey<V> {}

impl<V: Variant> PublicKey<V> {
    /// Creates a public key from its components.
    pub fn new(x: V::Public, y: V::Public) -> Self {
        let encoded = x.encode();
        let fingerprint = u64::from_le_bytes(
            encoded[encoded.len() - 8..]
                .try_into()
                .expect("an encoded point is longer than 8 bytes"),
        );
        Self { x, y, fingerprint }
    }

    /// Computes the public key of `private`.
    pub fn from_private(private: &PrivateKey) -> Self {
        let generator = V::Public::generator();
        Self::new(
            private.x.expose(|x| generator * x),
            private.y.expose(|y| generator * y),
        )
    }

    /// Returns the `X` component.
    pub const fn x(&self) -> &V::Public {
        &self.x
    }

    /// Returns the `Y` component.
    pub const fn y(&self) -> &V::Public {
        &self.y
    }

    /// Returns whether either component is the identity.
    ///
    /// Decoding rejects such keys; this guards keys built in memory.
    fn degenerate(&self) -> bool {
        self.x == V::Public::zero() || self.y == V::Public::zero()
    }
}

impl<V: Variant> Write for PublicKey<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.x.write(buf);
        self.y.write(buf);
    }
}

impl<V: Variant> Read for PublicKey<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let public = Self::new(V::Public::read(buf)?, V::Public::read(buf)?);
        if public.degenerate() {
            return Err(CodecError::Invalid("PublicKey", "identity component"));
        }
        Ok(public)
    }
}

impl<V: Variant> FixedSize for PublicKey<V> {
    const SIZE: usize = 2 * V::Public::SIZE;
}

/// Returns a new key pair derived from `rng`.
pub fn keypair<R: CryptoRng, V: Variant>(rng: &mut R) -> (PrivateKey, PublicKey<V>) {
    let private = PrivateKey::random(rng);
    let public = PublicKey::from_private(&private);
    (private, public)
}

/// A Schnorr proof of knowledge of the private key behind a [`PublicKey`].
///
/// Aggregation is secure only over keys whose holders know `(x, y)`, so verify this proof before
/// accepting a public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofOfKnowledge {
    challenge: Scalar,
    x: Scalar,
    y: Scalar,
}

impl ProofOfKnowledge {
    /// Proves knowledge of `private` for `public` under `namespace`.
    pub fn prove<R: CryptoRng, V: Variant>(
        rng: &mut R,
        namespace: &[u8],
        private: &PrivateKey,
        public: &PublicKey<V>,
    ) -> Self {
        let generator = V::Public::generator();
        let r_x = Scalar::random(&mut *rng);
        let r_y = Scalar::random(&mut *rng);
        let challenge =
            proof_challenge::<V>(namespace, public, &(generator * &r_x), &(generator * &r_y));
        let x = private.x.expose(|x| r_x + &(challenge.clone() * x));
        let y = private.y.expose(|y| r_y + &(challenge.clone() * y));
        Self { challenge, x, y }
    }

    /// Verifies this proof for `public` under `namespace`.
    pub fn verify<V: Variant>(&self, namespace: &[u8], public: &PublicKey<V>) -> Result<(), Error> {
        if public.degenerate() {
            return Err(Error::InvalidSignature);
        }
        let generator = V::Public::generator();
        let commitment_x = generator * &self.x - &(public.x * &self.challenge);
        let commitment_y = generator * &self.y - &(public.y * &self.challenge);
        if proof_challenge::<V>(namespace, public, &commitment_x, &commitment_y) != self.challenge {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

impl Write for ProofOfKnowledge {
    fn write(&self, buf: &mut impl BufMut) {
        self.challenge.write(buf);
        self.x.write(buf);
        self.y.write(buf);
    }
}

impl Read for ProofOfKnowledge {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let cfg = ScalarReadCfg::AllowZero;
        Ok(Self {
            challenge: Scalar::read_cfg(buf, &cfg)?,
            x: Scalar::read_cfg(buf, &cfg)?,
            y: Scalar::read_cfg(buf, &cfg)?,
        })
    }
}

impl FixedSize for ProofOfKnowledge {
    const SIZE: usize = 3 * Scalar::SIZE;
}

/// Hashes the proof transcript to its challenge.
fn proof_challenge<V: Variant>(
    namespace: &[u8],
    public: &PublicKey<V>,
    commitment_x: &V::Public,
    commitment_y: &V::Public,
) -> Scalar {
    let mut transcript = public.encode().to_vec();
    commitment_x.write(&mut transcript);
    commitment_y.write(&mut transcript);
    Scalar::map(PROOF, &union_unique(namespace, &transcript))
}

/// Hashes `period` to the base every signer in it multiplies.
pub fn period_base<V: Variant>(period: &[u8]) -> V::Signature {
    V::Signature::hash_to_group(PERIOD, period)
}

/// Hashes a namespaced message signed in `period` to its scalar.
fn message_scalar(period: &[u8], namespace: &[u8], message: &[u8]) -> Scalar {
    Scalar::map(
        MESSAGE,
        &union_unique(period, &union_unique(namespace, message)),
    )
}

/// Signs a namespaced message in `period`.
///
/// # Warning
///
/// Signing two different messages in one period lets anyone forge this key's signature on any
/// message in that period. See the module documentation.
pub fn sign_message<V: Variant>(
    private: &PrivateKey,
    period: &[u8],
    namespace: &[u8],
    message: &[u8],
) -> V::Signature {
    sign_with_base::<V>(
        private,
        &period_base::<V>(period),
        period,
        namespace,
        message,
    )
}

/// Signs a namespaced message in `period` with a precomputed [`period_base`].
pub fn sign_with_base<V: Variant>(
    private: &PrivateKey,
    base: &V::Signature,
    period: &[u8],
    namespace: &[u8],
    message: &[u8],
) -> V::Signature {
    let c = message_scalar(period, namespace, message);
    let exponent = private
        .x
        .expose(|x| private.y.expose(|y| x.clone() + &(c * y)));
    *base * &exponent
}

/// Verifies a signature over a namespaced message in `period`.
///
/// # Warning
///
/// This function assumes a group check was already performed on `public` and `signature`.
pub fn verify_message<V: Variant>(
    public: &PublicKey<V>,
    period: &[u8],
    namespace: &[u8],
    message: &[u8],
    signature: &V::Signature,
) -> Result<(), Error> {
    if public.degenerate() {
        return Err(Error::InvalidSignature);
    }
    let c = message_scalar(period, namespace, message);
    let combined = public.x + &(public.y * &c);
    V::verify(&combined, &period_base::<V>(period), signature)
}

/// A public key and the namespaced message it signed.
#[derive(Clone, Debug)]
pub struct Term<'a, V: Variant> {
    /// Public key of the signer.
    pub public: PublicKey<V>,
    /// Namespace the message was signed under.
    pub namespace: &'a [u8],
    /// Signed message.
    pub message: &'a [u8],
}

/// A signature over one or more [`Term`]s, all signed in one period.
///
/// A claim with one term is an ordinary signature. A claim with multiple terms is an aggregate
/// signature, such as a quorum certificate over distinct votes, and is accepted or rejected as a
/// unit.
#[derive(Clone, Debug)]
pub struct Claim<'a, V: Variant> {
    /// Period every term was signed in.
    pub period: &'a [u8],
    /// Signature, or aggregate signature, over every term.
    pub signature: V::Signature,
    /// Terms the signature covers.
    pub terms: Vec<Term<'a, V>>,
}

/// Window of the precomputed rows in a [`KeyTable`]: `2^(WINDOW - 1)` multiples per key
/// component.
const WINDOW: usize = 8;

/// Precomputed multiples of a committee's public keys, for [`verify_claims_with_table`].
///
/// Committee keys stay fixed across many batches, so their multiples are computed once. Each key
/// stores `2^(WINDOW - 1)` multiples of `X` and of `Y`.
pub struct KeyTable<V: Variant>
where
    V::Public: FixedBase,
{
    indices: HashMap<PublicKey<V>, usize>,
    x: <V::Public as FixedBase>::Table,
    y: <V::Public as FixedBase>::Table,
}

impl<V: Variant> KeyTable<V>
where
    V::Public: FixedBase,
{
    /// Precomputes the multiples of every key in `keys`.
    ///
    /// Repeated keys and keys with an identity component are left out; claims over them are still
    /// verified, without the table.
    pub fn new(keys: &[PublicKey<V>]) -> Self {
        let mut indices = HashMap::with_capacity(keys.len());
        let mut xs = Vec::with_capacity(keys.len());
        let mut ys = Vec::with_capacity(keys.len());
        for key in keys {
            if key.degenerate() || indices.contains_key(key) {
                continue;
            }
            indices.insert(*key, xs.len());
            xs.push(key.x);
            ys.push(key.y);
        }
        Self {
            indices,
            x: V::Public::precompute(&xs, WINDOW),
            y: V::Public::precompute(&ys, WINDOW),
        }
    }

    /// Returns the number of keys in the table.
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Returns whether the table has no keys.
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }
}

/// The terms of one claim that sign one namespaced message.
struct Group<'a, V: Variant> {
    /// Sum of the terms' `Y`.
    y: V::Public,
    /// Table index of the key, when the group is one term whose key is in the table.
    key: Option<usize>,
    message: (&'a [u8], &'a [u8]),
}

/// A structurally valid claim with its terms grouped by message.
struct CanonicalClaim<'a, V: Variant> {
    /// Position of the claim in the caller's slice.
    index: usize,
    /// Index of the claim's period.
    period: usize,
    signature: V::Signature,
    /// Sum of every term's `X`.
    x: V::Public,
    /// Table index of the key, when the claim has one term whose key is in the table.
    x_key: Option<usize>,
    groups: Vec<Group<'a, V>>,
}

/// Verifies independently supplied claims and returns the indices of invalid claims, in
/// ascending order.
///
/// Claims are randomly scaled so invalid signatures cannot cancel across claims. A claim is
/// structurally invalid, and reported without entering the batch, if its signature is zero, it
/// has no terms, one of its public keys has an identity component or is repeated, or the `Y`
/// components of the keys signing one message sum to zero.
///
/// # Performance
///
/// The batch costs one pairing per distinct period plus one, however many keys and messages it
/// covers. Each period adds one MSM over the `X` sums of its claims and one over the summed `Y`
/// of each distinct message, so terms that sign the same message cost one scalar multiplication
/// together. If the batch fails, bisection isolates the invalid claims, reusing the batch's
/// scalars. [`verify_claims_with_table`] speeds up the MSMs for keys of a fixed committee.
///
/// # Warning
///
/// This function assumes every public key and signature was group-checked while decoding, and
/// that every public key's [`ProofOfKnowledge`] was verified.
pub fn verify_claims<R, V>(
    rng: &mut R,
    claims: &[Claim<'_, V>],
    strategy: &impl Strategy,
) -> Vec<usize>
where
    R: CryptoRng,
    V: Variant,
    V::Public: FixedBase,
{
    verify(rng, claims, None, strategy)
}

/// Verifies claims like [`verify_claims`], multiplying keys in `table` by their precomputed
/// multiples.
///
/// The verdicts are identical to [`verify_claims`]; only the cost differs. Keys outside the table
/// are verified without it.
pub fn verify_claims_with_table<R, V>(
    rng: &mut R,
    claims: &[Claim<'_, V>],
    table: &KeyTable<V>,
    strategy: &impl Strategy,
) -> Vec<usize>
where
    R: CryptoRng,
    V: Variant,
    V::Public: FixedBase,
{
    verify(rng, claims, Some(table), strategy)
}

fn verify<R, V>(
    rng: &mut R,
    claims: &[Claim<'_, V>],
    table: Option<&KeyTable<V>>,
    strategy: &impl Strategy,
) -> Vec<usize>
where
    R: CryptoRng,
    V: Variant,
    V::Public: FixedBase,
{
    let mut invalid = Vec::new();
    let mut period_indices = HashMap::new();
    let mut periods = Vec::new();
    let mut pending: Vec<CanonicalClaim<'_, V>> = Vec::with_capacity(claims.len());
    for (index, claim) in claims.iter().enumerate() {
        let Some((x, x_key, groups)) = canonicalize(claim, table) else {
            invalid.push(index);
            continue;
        };
        let period = *period_indices.entry(claim.period).or_insert_with(|| {
            periods.push(claim.period);
            periods.len() - 1
        });
        pending.push(CanonicalClaim {
            index,
            period,
            signature: claim.signature,
            x,
            x_key,
            groups,
        });
    }
    if pending.is_empty() {
        return invalid;
    }

    // Draw scalars before parallel work so RNG consumption is independent of the strategy.
    let scalars = random_scalars(rng, pending.len());
    let failed = Batch::new(&pending, &periods, table, strategy).verify(&scalars, strategy);
    invalid.extend(failed.into_iter().map(|position| pending[position].index));
    invalid.sort_unstable();
    invalid
}

/// Checks a claim's structure and groups its terms by message.
///
/// Returns the sum of every `X`, the key's table index when the claim has one term in `table`,
/// and the terms grouped per distinct message, or `None` if the claim is structurally invalid
/// (see [`verify_claims`]).
#[allow(clippy::type_complexity)]
fn canonicalize<'a, V>(
    claim: &Claim<'a, V>,
    table: Option<&KeyTable<V>>,
) -> Option<(V::Public, Option<usize>, Vec<Group<'a, V>>)>
where
    V: Variant,
    V::Public: FixedBase,
{
    if claim.signature == V::Signature::zero() || claim.terms.is_empty() {
        return None;
    }

    // Each key is hashed once, to find its table row or, outside the table, to detect repeats.
    // Both sets are sized up front: hashing a key compresses its points, and a set that grows
    // hashes every key again.
    let capacity = claim.terms.len();
    let mut indices = HashSet::with_capacity(if table.is_some() { capacity } else { 0 });
    let mut publics = HashSet::with_capacity(capacity);
    let mut x = V::Public::zero();
    let mut groups = Vec::with_capacity(claim.terms.len());
    for term in &claim.terms {
        if term.public.degenerate() {
            return None;
        }
        let key = table.and_then(|table| table.indices.get(&term.public).copied());
        let fresh = key.map_or_else(
            || publics.insert(term.public),
            |index| indices.insert(index),
        );
        if !fresh {
            return None;
        }
        x += &term.public.x;
        groups.push(Group {
            y: term.public.y,
            key,
            message: (term.namespace, term.message),
        });
    }
    let x_key = if groups.len() == 1 {
        groups[0].key
    } else {
        None
    };

    groups.sort_unstable_by(|left, right| left.message.cmp(&right.message));
    groups.dedup_by(|next, current| {
        if next.message != current.message {
            return false;
        }
        current.y += &next.y;
        current.key = None;
        true
    });
    if groups.iter().any(|group| group.y == V::Public::zero()) {
        return None;
    }
    Some((x, x_key, groups))
}

/// A point term of a period's MSM, multiplied either through a [`KeyTable`] or directly.
enum Base<P> {
    /// Row of the `X` or `Y` table, depending on the MSM.
    Key(usize),
    Point(P),
}

/// Terms of one MSM, split between table rows and direct points.
struct Terms<P> {
    keys: Vec<(usize, Scalar)>,
    points: Vec<P>,
    scalars: Vec<Scalar>,
}

impl<P> Default for Terms<P> {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            points: Vec::new(),
            scalars: Vec::new(),
        }
    }
}

impl<P: Space<Scalar> + FixedBase> Terms<P> {
    fn push(&mut self, base: Base<P>, scalar: Scalar) {
        match base {
            Base::Key(index) => self.keys.push((index, scalar)),
            Base::Point(point) => {
                self.points.push(point);
                self.scalars.push(scalar);
            }
        }
    }

    /// Returns the sum of every term, using `table` for table rows.
    fn sum(&self, table: Option<&P::Table>, strategy: &impl Strategy) -> P {
        let direct = P::msm(&self.points, &self.scalars, strategy);
        match table {
            Some(table) if !self.keys.is_empty() => direct + &P::mul_table(table, &self.keys),
            _ => direct,
        }
    }
}

/// Pending claims with every period base and message scalar computed once.
struct Batch<'t, V: Variant>
where
    V::Public: FixedBase,
{
    table: Option<&'t KeyTable<V>>,
    /// Base of each distinct period.
    bases: Vec<V::Signature>,
    /// Period index of each claim.
    periods: Vec<usize>,
    /// Signature of each claim.
    signatures: Vec<V::Signature>,
    /// Summed `X` of each claim.
    xs: Vec<V::Public>,
    /// Table index of each single-key claim's `X`.
    x_keys: Vec<Option<usize>>,
    /// Scalar of each distinct message, which is distinct per period.
    scalars: Vec<Scalar>,
    /// Period index of each distinct message.
    message_periods: Vec<usize>,
    /// Summed `Y`, table index, and message index of every message group.
    groups: Vec<(V::Public, Option<usize>, usize)>,
    /// Claim `i` owns `groups[group_offsets[i]..group_offsets[i + 1]]`.
    group_offsets: Vec<usize>,
}

impl<'t, V: Variant> Batch<'t, V>
where
    V::Public: FixedBase,
{
    /// Hashes every distinct period and every distinct message once.
    fn new(
        pending: &[CanonicalClaim<'_, V>],
        periods: &[&[u8]],
        table: Option<&'t KeyTable<V>>,
        strategy: &impl Strategy,
    ) -> Self {
        let mut message_indices = HashMap::new();
        let mut messages = Vec::new();
        let mut groups = Vec::new();
        let mut group_offsets = Vec::with_capacity(pending.len() + 1);
        group_offsets.push(0);
        for claim in pending {
            for group in &claim.groups {
                let key = (claim.period, group.message.0, group.message.1);
                let message = *message_indices.entry(key).or_insert_with(|| {
                    messages.push(key);
                    messages.len() - 1
                });
                groups.push((group.y, group.key, message));
            }
            group_offsets.push(groups.len());
        }
        let (bases, scalars) = strategy.join(
            || strategy.map_collect_vec(periods, |period| period_base::<V>(period)),
            || {
                strategy.map_collect_vec(&messages, |(period, namespace, message)| {
                    message_scalar(periods[*period], namespace, message)
                })
            },
        );
        Self {
            table,
            bases,
            periods: pending.iter().map(|claim| claim.period).collect(),
            signatures: pending.iter().map(|claim| claim.signature).collect(),
            xs: pending.iter().map(|claim| claim.x).collect(),
            x_keys: pending.iter().map(|claim| claim.x_key).collect(),
            scalars,
            message_periods: messages.iter().map(|(period, _, _)| *period).collect(),
            groups,
            group_offsets,
        }
    }

    /// Returns the message groups of one claim.
    fn claim_groups(&self, claim: usize) -> &[(V::Public, Option<usize>, usize)] {
        &self.groups[self.group_offsets[claim]..self.group_offsets[claim + 1]]
    }

    /// Verifies the claims and returns the positions of invalid claims.
    fn verify(&self, scalars: &[SmallScalar], strategy: &impl Strategy) -> Vec<usize> {
        let claims = self.signatures.len();

        // Fast path: one MSM pair per period and one pairing product for the whole batch.
        let (publics, signature) = strategy.join(
            || self.period_publics(scalars, strategy),
            || V::Signature::msm(&self.signatures, scalars, strategy),
        );
        if V::verify_pairing_product(&publics, &self.bases, &signature, strategy).is_ok() {
            return Vec::new();
        }

        // Slow path: weight each claim once, then bisect with the batch's scalars.
        let weighted = strategy.map_collect_vec(0..claims, |claim| {
            let scalar = &scalars[claim];
            (
                self.claim_public(claim, scalar),
                self.signatures[claim] * scalar,
            )
        });
        bisect_ranges(claims, true, |_, range| {
            let mut publics = vec![V::Public::zero(); self.bases.len()];
            let mut signature = V::Signature::zero();
            for claim in range {
                publics[self.periods[claim]] += &weighted[claim].0;
                signature += &weighted[claim].1;
            }
            let (publics, bases): (Vec<_>, Vec<_>) = publics
                .into_iter()
                .zip(&self.bases)
                .filter(|(public, _)| public != &V::Public::zero())
                .map(|(public, base)| (public, *base))
                .unzip();
            V::verify_pairing_product(&publics, &bases, &signature, strategy).is_ok()
        })
    }

    /// Returns `sum_j r_j (X_j + sum_g c_g Y_g)` over the claims of each period, in period order.
    ///
    /// A message signed in at least [`FOLD_MIN`] claims folds their weights into its summed `Y`
    /// with one MSM and then takes its message scalar once, so claims that agree cost about as
    /// little as one aggregate.
    fn period_publics(&self, scalars: &[SmallScalar], strategy: &impl Strategy) -> Vec<V::Public> {
        let x_table = self.table.map(|table| &table.x);
        let y_table = self.table.map(|table| &table.y);
        let mut xs: Vec<Terms<V::Public>> =
            (0..self.bases.len()).map(|_| Terms::default()).collect();
        let mut members: Vec<Vec<(Base<V::Public>, Scalar)>> =
            (0..self.scalars.len()).map(|_| Vec::new()).collect();
        for (claim, scalar) in scalars.iter().enumerate() {
            let weight = Scalar::from(scalar.clone());
            let base = self.x_keys[claim].map_or(Base::Point(self.xs[claim]), Base::Key);
            xs[self.periods[claim]].push(base, weight.clone());
            for (y, key, message) in self.claim_groups(claim) {
                let base = key.map_or(Base::Point(*y), Base::Key);
                members[*message].push((base, weight.clone()));
            }
        }

        let mut ys: Vec<Terms<V::Public>> =
            (0..self.bases.len()).map(|_| Terms::default()).collect();
        for (message, members) in members.into_iter().enumerate() {
            let c = &self.scalars[message];
            let y = &mut ys[self.message_periods[message]];
            if members.len() < FOLD_MIN {
                for (base, weight) in members {
                    y.push(base, weight * c);
                }
                continue;
            }
            let mut folded = Terms::default();
            for (base, weight) in members {
                folded.push(base, weight);
            }
            y.push(Base::Point(folded.sum(y_table, strategy)), c.clone());
        }

        xs.iter()
            .zip(&ys)
            .map(|(x, y)| x.sum(x_table, strategy) + &y.sum(y_table, strategy))
            .collect()
    }

    /// Returns `r (X + sum_g c_g Y_g)` for one claim.
    fn claim_public(&self, claim: usize, scalar: &SmallScalar) -> V::Public {
        let full = Scalar::from(scalar.clone());
        let (ys, cs): (Vec<_>, Vec<_>) = self
            .claim_groups(claim)
            .iter()
            .map(|(y, _, message)| (*y, full.clone() * &self.scalars[*message]))
            .unzip();
        self.xs[claim] * scalar + &<V::Public as Space<Scalar>>::msm(&ys, &cs, &Sequential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::variant::{MinPk, MinSig};
    use commonware_codec::DecodeExt;
    use commonware_math::algebra::Field;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{NZUsize, test_rng};

    const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_SAS_TEST";

    fn keys<V: Variant>(count: usize) -> Vec<(PrivateKey, PublicKey<V>)> {
        let mut rng = test_rng();
        (0..count).map(|_| keypair::<_, V>(&mut rng)).collect()
    }

    fn sign_verify<V: Variant<Public: FixedBase>>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        let signature = sign_message::<V>(&private, b"view-1", NAMESPACE, b"message");
        verify_message::<V>(&public, b"view-1", NAMESPACE, b"message", &signature).unwrap();
        assert!(
            verify_message::<V>(&public, b"view-2", NAMESPACE, b"message", &signature).is_err()
        );
        assert!(verify_message::<V>(&public, b"view-1", NAMESPACE, b"other", &signature).is_err());
        assert!(verify_message::<V>(&public, b"view-1", b"other", b"message", &signature).is_err());
        assert!(
            verify_message::<V>(
                &public,
                b"view-1",
                NAMESPACE,
                b"message",
                &V::Signature::zero()
            )
            .is_err()
        );
    }

    #[test]
    fn test_sign_verify() {
        sign_verify::<MinPk>();
        sign_verify::<MinSig>();
    }

    fn sign_with_base_matches<V: Variant<Public: FixedBase>>() {
        let (private, _) = keypair::<_, V>(&mut test_rng());
        let base = period_base::<V>(b"view-1");
        assert_eq!(
            sign_with_base::<V>(&private, &base, b"view-1", NAMESPACE, b"message"),
            sign_message::<V>(&private, b"view-1", NAMESPACE, b"message"),
        );
    }

    #[test]
    fn test_sign_with_base_matches() {
        sign_with_base_matches::<MinPk>();
        sign_with_base_matches::<MinSig>();
    }

    /// Builds an aggregate claim in which signer `i` signs message `i % distinct`.
    fn aggregate<'a, V: Variant>(
        keys: &[(PrivateKey, PublicKey<V>)],
        period: &'a [u8],
        messages: &'a [Vec<u8>],
    ) -> Claim<'a, V> {
        let mut signature = V::Signature::zero();
        let terms = keys
            .iter()
            .enumerate()
            .map(|(index, (private, public))| {
                let message = &messages[index % messages.len()];
                signature += &sign_message::<V>(private, period, NAMESPACE, message);
                Term {
                    public: *public,
                    namespace: NAMESPACE,
                    message,
                }
            })
            .collect();
        Claim {
            period,
            signature,
            terms,
        }
    }

    fn messages(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| format!("message {i}").into_bytes())
            .collect()
    }

    fn aggregate_verifies<V: Variant<Public: FixedBase>>() {
        let keys = keys::<V>(7);
        for distinct in [1, 3, 7] {
            let messages = messages(distinct);
            let claim = aggregate(&keys, b"view-1", &messages);
            assert!(
                verify_claims(&mut test_rng(), core::slice::from_ref(&claim), &Sequential)
                    .is_empty()
            );

            // Wrong period, swapped message, and forged signature all fail.
            let mut wrong_period = claim.clone();
            wrong_period.period = b"view-2";
            let mut swapped = claim.clone();
            swapped.terms[0].message = b"forged";
            let mut forged = claim.clone();
            forged.signature += &V::Signature::generator();
            let rayon = Rayon::new(NZUsize!(4)).unwrap();
            assert_eq!(
                verify_claims(
                    &mut test_rng(),
                    &[claim, wrong_period, swapped, forged],
                    &rayon
                ),
                vec![1, 2, 3]
            );
        }
    }

    #[test]
    fn test_aggregate_verifies() {
        aggregate_verifies::<MinPk>();
        aggregate_verifies::<MinSig>();
    }

    fn structural_rejections<V: Variant<Public: FixedBase>>() {
        let keys = keys::<V>(3);
        let messages = messages(3);
        let valid = aggregate(&keys, b"view-1", &messages);

        let mut zero = valid.clone();
        zero.signature = V::Signature::zero();
        let mut empty = valid.clone();
        empty.terms.clear();
        let mut repeated = valid.clone();
        repeated.terms[1].public = repeated.terms[0].public;
        let mut degenerate = valid.clone();
        degenerate.terms[0].public.y = V::Public::zero();

        assert_eq!(
            verify_claims(
                &mut test_rng(),
                &[zero, valid, empty, repeated, degenerate],
                &Sequential
            ),
            vec![0, 2, 3, 4]
        );
    }

    #[test]
    fn test_structural_rejections() {
        structural_rejections::<MinPk>();
        structural_rejections::<MinSig>();
    }

    /// Bisection finds exactly the invalid claims when they span several periods.
    fn bisection_across_periods<V: Variant<Public: FixedBase>>() {
        let keys = keys::<V>(12);
        let periods: [&[u8]; 3] = [b"height-1", b"height-2", b"height-3"];
        let messages = messages(keys.len());
        let mut claims: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(index, (private, public))| {
                let period = periods[index % periods.len()];
                let message = &messages[index];
                Claim {
                    period,
                    signature: sign_message::<V>(private, period, NAMESPACE, message),
                    terms: vec![Term {
                        public: *public,
                        namespace: NAMESPACE,
                        message,
                    }],
                }
            })
            .collect();
        assert!(verify_claims(&mut test_rng(), &claims, &Sequential).is_empty());

        let rayon = Rayon::new(NZUsize!(4)).unwrap();
        for invalid in [vec![5], vec![0, 4, 11], vec![1, 2, 3, 7]] {
            let mut tampered = claims.clone();
            for &index in &invalid {
                tampered[index].signature += &V::Signature::generator();
            }
            assert_eq!(
                verify_claims(&mut test_rng(), &tampered, &Sequential),
                invalid
            );
            assert_eq!(verify_claims(&mut test_rng(), &tampered, &rayon), invalid);
        }

        // Errors that cancel within the batch are still caught.
        claims[0].signature += &V::Signature::generator();
        claims[1].signature -= &V::Signature::generator();
        assert_eq!(
            verify_claims(&mut test_rng(), &claims, &Sequential),
            vec![0, 1]
        );
    }

    /// Independent claims over shared messages still isolate bad claims, both for messages
    /// signed often enough to fold and for messages signed by a few claims.
    fn shared_messages<V: Variant<Public: FixedBase>>() {
        // Four (period, message) pairs signed FOLD_MIN times each, then one signed twice per period.
        let folded = 4 * FOLD_MIN;
        let keys = keys::<V>(folded + 4);
        let periods: [&[u8]; 2] = [b"view-1", b"view-2"];
        let messages = messages(3);
        let claims: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(index, (private, public))| {
                let period = periods[index % 2];
                let message = if index < folded {
                    &messages[(index / 2) % 2]
                } else {
                    &messages[2]
                };
                Claim {
                    period,
                    signature: sign_message::<V>(private, period, NAMESPACE, message),
                    terms: vec![Term {
                        public: *public,
                        namespace: NAMESPACE,
                        message,
                    }],
                }
            })
            .collect();
        let rayon = Rayon::new(NZUsize!(4)).unwrap();
        assert!(verify_claims(&mut test_rng(), &claims, &Sequential).is_empty());
        assert!(verify_claims(&mut test_rng(), &claims, &rayon).is_empty());

        for invalid in [vec![3], vec![0, 1, folded + 2]] {
            let mut tampered = claims.clone();
            for &index in &invalid {
                tampered[index].signature += &V::Signature::generator();
            }
            assert_eq!(
                verify_claims(&mut test_rng(), &tampered, &Sequential),
                invalid
            );
            assert_eq!(verify_claims(&mut test_rng(), &tampered, &rayon), invalid);
        }

        // A signature moved between two signers of one message cancels in the unweighted sum.
        let mut swapped = claims;
        let moved = swapped[0].signature;
        swapped[0].signature = swapped[4].signature;
        swapped[4].signature = moved;
        assert_eq!(
            verify_claims(&mut test_rng(), &swapped, &Sequential),
            vec![0, 4]
        );
    }

    /// Signs `message` in `period` as a single-term claim.
    fn single<'a, V: Variant>(
        (private, public): &(PrivateKey, PublicKey<V>),
        period: &'a [u8],
        message: &'a [u8],
    ) -> Claim<'a, V> {
        Claim {
            period,
            signature: sign_message::<V>(private, period, NAMESPACE, message),
            terms: vec![Term {
                public: *public,
                namespace: NAMESPACE,
                message,
            }],
        }
    }

    /// Asserts that `claims` fail exactly at `expected`, without a table and with each of `tables`.
    fn check<V: Variant<Public: FixedBase>>(
        claims: &[Claim<'_, V>],
        tables: &[KeyTable<V>],
        expected: &[usize],
    ) {
        assert_eq!(
            verify_claims(&mut test_rng(), claims, &Sequential),
            expected
        );
        for table in tables {
            assert_eq!(
                verify_claims_with_table(&mut test_rng(), claims, table, &Sequential),
                expected
            );
        }
    }

    /// Verdicts with full, partial, and empty tables match verdicts without one.
    fn table_matches_untabled<V: Variant<Public: FixedBase>>() {
        let keys = keys::<V>(FOLD_MIN + 8);
        let publics: Vec<_> = keys.iter().map(|(_, public)| *public).collect();
        let tables = [
            KeyTable::new(&publics),
            KeyTable::new(&publics[..publics.len() / 2]),
            KeyTable::new(&[]),
        ];
        let messages = messages(keys.len());

        // Certificates over 1, 5, and all-distinct messages.
        for distinct in [1, 5, keys.len()] {
            let claim = aggregate(&keys, b"view-1", &messages[..distinct]);
            let mut forged = claim.clone();
            forged.signature += &V::Signature::generator();
            let mut repeated = claim.clone();
            repeated.terms[1].public = repeated.terms[0].public;
            let mut repeated_outside = claim.clone();
            let last = repeated_outside.terms.len() - 1;
            repeated_outside.terms[last - 1].public = repeated_outside.terms[last].public;
            check(
                &[claim, forged, repeated, repeated_outside],
                &tables,
                &[1, 2, 3],
            );
        }

        // Independent votes over one message (folded) and blocks across three periods.
        let periods: [&[u8]; 3] = [b"height-1", b"height-2", b"height-3"];
        let votes: Vec<_> = keys
            .iter()
            .map(|key| single(key, b"view-1", b"vote"))
            .collect();
        let blocks: Vec<_> = keys
            .iter()
            .zip(&messages)
            .enumerate()
            .map(|(index, (key, message))| single(key, periods[index % periods.len()], message))
            .collect();
        for claims in [votes, blocks] {
            check(&claims, &tables, &[]);
            let mut tampered = claims.clone();
            for index in [0, 7, claims.len() - 1] {
                tampered[index].signature += &V::Signature::generator();
            }
            check(&tampered, &tables, &[0, 7, claims.len() - 1]);
            let mut cancelling = claims;
            cancelling[2].signature += &V::Signature::generator();
            cancelling[3].signature -= &V::Signature::generator();
            check(&cancelling, &tables, &[2, 3]);
        }
    }

    #[test]
    fn test_table_matches_untabled() {
        table_matches_untabled::<MinPk>();
        table_matches_untabled::<MinSig>();
    }

    #[test]
    fn test_shared_messages() {
        shared_messages::<MinPk>();
        shared_messages::<MinSig>();
    }

    #[test]
    fn test_bisection_across_periods() {
        bisection_across_periods::<MinPk>();
        bisection_across_periods::<MinSig>();
    }

    /// Two signatures from one key over different messages in one period forge any message in
    /// that period. This is why a key must sign at most once per period.
    fn double_signing_forges<V: Variant<Public: FixedBase>>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        let period: &[u8] = b"view-1";
        let first = sign_message::<V>(&private, period, NAMESPACE, b"first");
        let second = sign_message::<V>(&private, period, NAMESPACE, b"second");

        // (B1 - B2) = (c1 - c2) y H1(t), then B1 - c1 y H1(t) = x H1(t).
        let c1 = message_scalar(period, NAMESPACE, b"first");
        let c2 = message_scalar(period, NAMESPACE, b"second");
        let y_base = (first - &second) * &(c1.clone() - &c2).inv();
        let x_base = first - &(y_base * &c1);
        let target = message_scalar(period, NAMESPACE, b"forged");
        let forgery = x_base + &(y_base * &target);
        verify_message::<V>(&public, period, NAMESPACE, b"forged", &forgery).unwrap();

        // The forgery does not carry over to another period.
        assert!(verify_message::<V>(&public, b"view-2", NAMESPACE, b"forged", &forgery).is_err());
    }

    #[test]
    fn test_double_signing_forges() {
        double_signing_forges::<MinPk>();
        double_signing_forges::<MinSig>();
    }

    /// Without a proof of knowledge, a rogue key cancels honest keys out of an aggregate.
    fn rogue_key_needs_proof<V: Variant<Public: FixedBase>>() {
        let mut rng = test_rng();
        let (_, honest) = keypair::<_, V>(&mut rng);
        let (rogue_private, rogue_public) = keypair::<_, V>(&mut rng);
        let rogue = PublicKey::<V>::new(rogue_public.x - &honest.x, rogue_public.y - &honest.y);

        // Both "sign" the same message: the attacker alone produces the aggregate.
        let period: &[u8] = b"view-1";
        let signature = sign_message::<V>(&rogue_private, period, NAMESPACE, b"message");
        let claim = Claim {
            period,
            signature,
            terms: vec![
                Term {
                    public: honest,
                    namespace: NAMESPACE,
                    message: b"message",
                },
                Term {
                    public: rogue,
                    namespace: NAMESPACE,
                    message: b"message",
                },
            ],
        };
        assert!(verify_claims(&mut rng, &[claim], &Sequential).is_empty());

        // The rogue key cannot prove knowledge of its secrets.
        let proof = ProofOfKnowledge::prove(&mut rng, NAMESPACE, &rogue_private, &rogue);
        assert!(proof.verify(NAMESPACE, &rogue).is_err());
    }

    #[test]
    fn test_rogue_key_needs_proof() {
        rogue_key_needs_proof::<MinPk>();
        rogue_key_needs_proof::<MinSig>();
    }

    fn proof_of_knowledge<V: Variant<Public: FixedBase>>() {
        let mut rng = test_rng();
        let (private, public) = keypair::<_, V>(&mut rng);
        let proof = ProofOfKnowledge::prove(&mut rng, NAMESPACE, &private, &public);
        proof.verify(NAMESPACE, &public).unwrap();
        assert!(proof.verify(b"other", &public).is_err());
        let (_, other) = keypair::<_, V>(&mut rng);
        assert!(proof.verify(NAMESPACE, &other).is_err());

        let decoded = ProofOfKnowledge::decode(proof.encode()).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn test_proof_of_knowledge() {
        proof_of_knowledge::<MinPk>();
        proof_of_knowledge::<MinSig>();
    }

    fn codec<V: Variant<Public: FixedBase>>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        assert_eq!(PublicKey::<V>::decode(public.encode()).unwrap(), public);
        assert_eq!(PrivateKey::decode(private.encode()).unwrap(), private);

        let degenerate = PublicKey::<V>::new(public.x, V::Public::zero());
        assert!(PublicKey::<V>::decode(degenerate.encode()).is_err());
    }

    #[test]
    fn test_codec() {
        codec::<MinPk>();
        codec::<MinSig>();
    }
}
