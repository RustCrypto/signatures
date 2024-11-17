use core::ops::{Add, Mul, Neg, Sub};
use hybrid_array::{
    typenum::{Unsigned, U256},
    Array,
};

use crate::crypto::{G, H};
use crate::param::{ArraySize, Eta, MaskSamplingSize};
use crate::util::Truncate;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub type Integer = u32;

/// An element of GF(q)
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct FieldElement(pub Integer);

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl FieldElement {
    pub const Q: Integer = 8380417;
    pub const Q64: u64 = Self::Q as u64;
    pub const ONE: Self = Self(1);
    pub const MINUS_ONE: Self = Self(Self::Q - 1);

    // Algorithm 14 CoeffFromThreeBytes
    fn from_three_bytes(b: &[u8; 3]) -> Option<Self> {
        let b0: Integer = b[0].into();
        let b1: Integer = b[1].into();
        let b2: Integer = b[2].into();

        let b2p = if b2 > 127 { b2 - 128 } else { b2 };

        let z = (b2p << 16) + (b1 << 8) + b0;
        (z < Self::Q).then_some(FieldElement(z))
    }

    // Algorithm 15 CoeffFromHalfByte
    fn from_half_byte(b: u8, eta: Eta) -> Option<Self> {
        if matches!(eta, Eta::Two) && b < 15 {
            Some(Self(2) - Self((b as Integer) % 5))
        } else if matches!(eta, Eta::Four) && b < 9 {
            Some(Self(4) - Self(b as Integer))
        } else {
            None
        }

        /* XXX(RLB) Slightly more elegant version IMO
        match eta {
            Eta::Two if b < 15 => {
                let b = (b as Integer) % 5;
                if b <= 2 {
                    Some(Self(2 - b))
                } else {
                    Some(-Self(b - 2))
                }
            }
            Eta::Four if b < 9 => {
                let b = b as Integer;
                if b <= 4 {
                    Some(Self(4 - b))
                } else {
                    Some(-Self(b - 4))
                }
            }
            _ => None,
        }
        */
    }

    fn from_byte(z: u8, eta: Eta) -> (Option<Self>, Option<Self>) {
        (
            Self::from_half_byte(z & 0x0F, eta),
            Self::from_half_byte(z >> 4, eta),
        )
    }

    fn mod_plus_minus(&self, m: Self) -> Self {
        let raw_mod = Self(self.0 % m.0);
        if raw_mod.0 <= m.0 >> 1 {
            raw_mod
        } else {
            raw_mod - m
        }
    }

    // Algorithm 35 Power2Round
    //
    // XXX(RLB) In the specification, this function is specified as mapping to signed integers
    // rather than modular integers.  To avoid the need for a whole separate type for signed
    // integer polynomials, we represent these values using integers mod Q.  This is safe because Q
    // is much larger than 2^13, so there's no risk of overlap between positive numbers (x)
    // and negative numbers (Q-x).
    fn power2round(&self) -> (Self, Self) {
        const D: Integer = 13;
        const POW_2_D: Integer = 1 << D;

        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus(Self(POW_2_D));
        let r1 = FieldElement((r_plus - r0).0 >> D);

        (r1, r0)
    }

    // Algorithm 36 Decompose
    pub fn decompose<Gamma2: Unsigned>(&self) -> (Self, Self) {
        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus(Self(2 * Gamma2::U32));
        if r_plus - r0 == FieldElement(FieldElement::Q - 1) {
            (FieldElement(0), FieldElement(r0.0 - 1))
        } else {
            let mut r1 = r_plus - r0;
            r1.0 /= 2 * Gamma2::U32;
            (r1, r0)
        }
    }

    // Algorithm 37 HighBits
    pub fn high_bits<Gamma2: Unsigned>(&self) -> Self {
        self.decompose::<Gamma2>().0
    }

    // Algorithm 38 LowBits
    fn low_bits<Gamma2: Unsigned>(&self) -> Self {
        self.decompose::<Gamma2>().1
    }

    // FIPS 204 defines the infinity norm differently for signed vs. unsigned integers:
    //
    // * For w in Z, |w|_\infinity = |w|, the absolute value of w
    // * For w in Z_q, |W|_infinity = |w mod^\pm q|
    //
    // Note that these two definitions are equivalent if |w| < q/2.  This property holds for all of
    // the signed integers used in this crate, so we can safely use the unsigned version.  However,
    // since mod_plus_minus is also unsigned, we need to unwrap the "negative" values.
    pub fn infinity_norm(&self) -> u32 {
        if self.0 <= Self::Q >> 1 {
            self.0
        } else {
            Self::Q - self.0
        }
    }

    // A fast modular reduction for small numbers `x < 2*q`
    fn small_reduce(x: u32) -> u32 {
        if x < Self::Q {
            x
        } else {
            x - Self::Q
        }
    }

    fn barrett_reduce(x: u64) -> u32 {
        // TODO
        (x % Self::Q64).truncate()

        /*
        let product = u64::from(x) * Self::BARRETT_MULTIPLIER;
        let quotient = (product >> Self::BARRETT_SHIFT).truncate();
        let remainder = x - quotient * Self::Q32;
        Self::small_reduce(remainder.truncate())
        */
    }
}

impl From<FieldElement> for u128 {
    fn from(x: FieldElement) -> u128 {
        x.0.into()
    }
}

impl From<u128> for FieldElement {
    fn from(x: u128) -> FieldElement {
        FieldElement(x.truncate())
    }
}

impl Add<FieldElement> for FieldElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(Self::small_reduce(self.0 + rhs.0))
    }
}

impl Sub<FieldElement> for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        // Guard against underflow if `rhs` is too large
        Self(Self::small_reduce(self.0 + Self::Q - rhs.0))
    }
}

impl Mul<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        let x = u64::from(self.0);
        let y = u64::from(rhs.0);
        Self(Self::barrett_reduce(x * y))
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        Self(Self::Q - self.0)
    }
}

// Algorithm 13 BytesToBits
fn bit_set(z: &[u8], i: usize) -> bool {
    let bit_index = i % 8;
    let byte_index = i >> 3;
    (z[byte_index] >> bit_index) == 1
}

/// An element of the ring `R_q`, i.e., a polynomial over `Z_q` of degree 255
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Polynomial(pub Array<FieldElement, U256>);

impl Polynomial {
    fn mod_plus_minus(&self, m: FieldElement) -> Self {
        Self(self.0.iter().map(|x| x.mod_plus_minus(m)).collect())
    }

    fn high_bits<Gamma2: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(|x| x.high_bits::<Gamma2>()).collect())
    }

    fn low_bits<Gamma2: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(|x| x.low_bits::<Gamma2>()).collect())
    }

    fn infinity_norm(&self) -> u32 {
        self.0.iter().map(|x| x.infinity_norm()).max().unwrap()
    }

    // Algorithm 29 SampleInBall
    pub fn sample_in_ball(rho: &[u8], tau: usize) -> Self {
        const ONE: FieldElement = FieldElement(1);
        const MINUS_ONE: FieldElement = FieldElement(FieldElement::Q - 1);

        let mut c = Self::default();
        let mut ctx = H::default().absorb(rho);

        let mut s = [0u8; 8];
        ctx.squeeze(&mut s);

        // h == bytes_to_bits(s)
        let mut j = [0u8];
        for i in (256 - tau)..256 {
            ctx.squeeze(&mut j);
            while (j[0] as usize) > i {
                ctx.squeeze(&mut j);
            }

            let j = j[0] as usize;
            c.0[i] = c.0[j];
            c.0[j] = if bit_set(&s, i + tau - 256) {
                MINUS_ONE
            } else {
                ONE
            };
        }

        c
    }

    // Algorithm 31 RejBoundedPoly
    fn rej_bounded_poly(rho: &[u8], eta: Eta, r: u16) -> Self {
        let mut j = 0;
        let mut ctx = H::default().absorb(rho).absorb(&r.to_le_bytes());

        let mut a = Self::default();
        let mut z = [0u8];
        while j < 256 {
            ctx.squeeze(&mut z);
            let (z0, z1) = FieldElement::from_byte(z[0], eta);

            if let Some(z) = z0 {
                a.0[j] = z;
                j += 1;
            }

            if j == 256 {
                break;
            }

            if let Some(z) = z1 {
                a.0[j] = z;
                j += 1;
            }
        }

        a
    }

    // Algorithm 35 Power2Round
    fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }
}

impl Add<&Polynomial> for &Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: &Polynomial) -> Polynomial {
        Polynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x + y)
                .collect(),
        )
    }
}

impl Sub<&Polynomial> for &Polynomial {
    type Output = Polynomial;

    fn sub(self, rhs: &Polynomial) -> Polynomial {
        Polynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x - y)
                .collect(),
        )
    }
}

impl Neg for &Polynomial {
    type Output = Polynomial;

    fn neg(self) -> Polynomial {
        Polynomial(self.0.iter().map(|&x| -x).collect())
    }
}

impl Mul<&Polynomial> for FieldElement {
    type Output = Polynomial;

    fn mul(self, rhs: &Polynomial) -> Polynomial {
        Polynomial(rhs.0.iter().map(|&x| self * x).collect())
    }
}

/// A vector of polynomials of length `k`
#[derive(Clone, Default, Debug, PartialEq)]
pub struct PolynomialVector<K: ArraySize>(pub Array<Polynomial, K>);

impl<K: ArraySize> PolynomialVector<K> {
    pub fn mod_plus_minus(&self, m: FieldElement) -> Self {
        Self(self.0.iter().map(|x| x.mod_plus_minus(m)).collect())
    }

    // Algorithm 33 ExpandS
    //
    // We only do half of the algorithm here, because it's inconvenient to return two vectors of
    // different sizes.  So the caller has to call twice:
    //
    //    let s1 = PolynomialVector::<K>::expand_s(rho, 0);
    //    let s2 = PolynomialVector::<L>::expand_s(rho, L::USIZE);
    pub fn expand_s(rho: &[u8], eta: Eta, base: usize) -> Self {
        Self(Array::from_fn(|r| {
            let r = (r + base) as u16;
            Polynomial::rej_bounded_poly(rho, eta, r)
        }))
    }

    pub fn expand_mask<Gamma1>(rho: &[u8], mu: u16) -> Self
    where
        Gamma1: MaskSamplingSize,
    {
        Self(Array::from_fn(|r| {
            let r16: u16 = r.truncate();
            let v = H::default()
                .absorb(rho)
                .absorb(&(mu + r16).to_le_bytes())
                .squeeze_new::<Gamma1::SampleSize>();

            Gamma1::unpack(&v)
        }))
    }

    pub fn high_bits<Gamma2: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(|x| x.high_bits::<Gamma2>()).collect())
    }

    pub fn low_bits<Gamma2: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(|x| x.low_bits::<Gamma2>()).collect())
    }

    pub fn infinity_norm(&self) -> u32 {
        self.0.iter().map(|x| x.infinity_norm()).max().unwrap()
    }

    // Algorithm 35 Power2Round
    pub fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }
}

impl<K: ArraySize> Add<&PolynomialVector<K>> for &PolynomialVector<K> {
    type Output = PolynomialVector<K>;

    fn add(self, rhs: &PolynomialVector<K>) -> PolynomialVector<K> {
        PolynomialVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x + y)
                .collect(),
        )
    }
}

impl<K: ArraySize> Sub<&PolynomialVector<K>> for &PolynomialVector<K> {
    type Output = PolynomialVector<K>;

    fn sub(self, rhs: &PolynomialVector<K>) -> PolynomialVector<K> {
        PolynomialVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x - y)
                .collect(),
        )
    }
}

impl<K: ArraySize> Neg for &PolynomialVector<K> {
    type Output = PolynomialVector<K>;

    fn neg(self) -> PolynomialVector<K> {
        PolynomialVector(self.0.iter().map(|x| -x).collect())
    }
}

impl<K: ArraySize> Mul<&PolynomialVector<K>> for FieldElement {
    type Output = PolynomialVector<K>;

    fn mul(self, rhs: &PolynomialVector<K>) -> PolynomialVector<K> {
        PolynomialVector(rhs.0.iter().map(|x| self * x).collect())
    }
}

/*
impl<K: ArraySize> PolynomialVector<K> {
    pub fn sample_cbd<Eta>(sigma: &B32, start_n: u8) -> Self
    where
        Eta: CbdSamplingSize,
    {
        Self(Array::from_fn(|i| {
            let N = start_n + i.truncate();
            let prf_output = PRF::<Eta>(sigma, N);
            Polynomial::sample_cbd::<Eta>(&prf_output)
        }))
    }
}
*/

/// An element of the ring `T_q`, i.e., a tuple of 128 elements of the direct sum components of `T_q`.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct NttPolynomial(pub Array<FieldElement, U256>);

impl NttPolynomial {
    // Algorithm 30 RejNTTPoly
    fn rej_ntt_poly(rho: &[u8], r: u8, s: u8) -> Self {
        let mut j = 0;
        let mut ctx = G::default().absorb(rho).absorb(&[s]).absorb(&[r]);

        let mut a = Self::default();
        let mut s = [0u8; 3];
        while j < 256 {
            ctx.squeeze(&mut s);
            if let Some(x) = FieldElement::from_three_bytes(&s) {
                a.0[j] = x;
                j += 1;
            }
        }

        a
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for NttPolynomial {
    fn zeroize(&mut self) {
        for fe in self.0.iter_mut() {
            fe.zeroize()
        }
    }
}

// Algorithm 44 AddNTT
impl Add<&NttPolynomial> for &NttPolynomial {
    type Output = NttPolynomial;

    fn add(self, rhs: &NttPolynomial) -> NttPolynomial {
        NttPolynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x + y)
                .collect(),
        )
    }
}

impl Sub<&NttPolynomial> for &NttPolynomial {
    type Output = NttPolynomial;

    fn sub(self, rhs: &NttPolynomial) -> NttPolynomial {
        NttPolynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x - y)
                .collect(),
        )
    }
}

/*
// Algorithm 6. SampleNTT (lines 4-13)
struct FieldElementReader<'a> {
    xof: &'a mut dyn XofReader,
    data: [u8; 96],
    start: usize,
    next: Option<Integer>,
}

impl<'a> FieldElementReader<'a> {
    fn new(xof: &'a mut impl XofReader) -> Self {
        let mut out = Self {
            xof,
            data: [0u8; 96],
            start: 0,
            next: None,
        };

        // Fill the buffer
        out.xof.read(&mut out.data);

        out
    }

    fn next(&mut self) -> FieldElement {
        if let Some(val) = self.next {
            self.next = None;
            return FieldElement(val);
        }

        loop {
            if self.start == self.data.len() {
                self.xof.read(&mut self.data);
                self.start = 0;
            }

            let end = self.start + 3;
            let b = &self.data[self.start..end];
            self.start = end;

            let d1 = Integer::from(b[0]) + ((Integer::from(b[1]) & 0xf) << 8);
            let d2 = (Integer::from(b[1]) >> 4) + ((Integer::from(b[2]) as Integer) << 4);

            if d1 < FieldElement::Q {
                if d2 < FieldElement::Q {
                    self.next = Some(d2);
                }
                return FieldElement(d1);
            }

            if d2 < FieldElement::Q {
                return FieldElement(d2);
            }
        }
    }
}

impl NttPolynomial {
    // Algorithm 6 SampleNTT(B)
    pub fn sample_uniform(B: &mut impl XofReader) -> Self {
        let mut reader = FieldElementReader::new(B);
        Self(Array::from_fn(|_| reader.next()))
    }
}
*/

// Since the powers of zeta used in the NTT and MultiplyNTTs are fixed, we use pre-computed tables
// to avoid the need to compute the exponetiations at runtime.
//
// * ZETA_POW_BITREV[i] = zeta^{BitRev_7(i)}
// * GAMMA[i] = zeta^{2 BitRev_7(i) + 1}
//
// Note that the const environment here imposes some annoying conditions.  Because operator
// overloading can't be const, we have to do all the reductions here manually.  Because `for` loops
// are forbidden in `const` functions, we do them manually with `while` loops.
//
// The values computed here match those provided in Appendix A of FIPS 203.  ZETA_POW_BITREV
// corresponds to the first table, and GAMMA to the second table.
#[allow(clippy::cast_possible_truncation)]
const ZETA_POW_BITREV: [FieldElement; 256] = {
    const ZETA: u64 = 1753;
    #[allow(clippy::integer_division_remainder_used)]
    const fn bitrev8(x: usize) -> usize {
        (x as u8).reverse_bits() as usize
    }

    // Compute the powers of zeta
    let mut pow = [FieldElement(0); 256];
    let mut i = 0;
    let mut curr = 1u64;
    #[allow(clippy::integer_division_remainder_used)]
    while i < 256 {
        pow[i] = FieldElement(curr as u32);
        i += 1;
        curr = (curr * ZETA) % FieldElement::Q64;
    }

    // Reorder the powers according to bitrev8
    // Note that entry 0 is left as zero, in order to match the `zetas` array in the
    // specification.
    let mut pow_bitrev = [FieldElement(0); 256];
    let mut i = 1;
    while i < 256 {
        pow_bitrev[i] = pow[bitrev8(i)];
        i += 1;
    }
    pow_bitrev
};

// Algorithm 45 MultiplyNTT
impl Mul<&NttPolynomial> for &NttPolynomial {
    type Output = NttPolynomial;

    fn mul(self, rhs: &NttPolynomial) -> NttPolynomial {
        NttPolynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x * y)
                .collect(),
        )
    }
}

impl From<Array<FieldElement, U256>> for NttPolynomial {
    fn from(f: Array<FieldElement, U256>) -> NttPolynomial {
        NttPolynomial(f)
    }
}

impl From<NttPolynomial> for Array<FieldElement, U256> {
    fn from(f_hat: NttPolynomial) -> Array<FieldElement, U256> {
        f_hat.0
    }
}

// Algorithm 41 NTT
impl Polynomial {
    pub fn ntt(&self) -> NttPolynomial {
        let mut w = self.0.clone();

        let mut m = 0;
        for len in [128, 64, 32, 16, 8, 4, 2, 1] {
            for start in (0..256).step_by(2 * len) {
                m += 1;
                let z = ZETA_POW_BITREV[m];

                for j in start..(start + len) {
                    let t = z * w[j + len];
                    w[j + len] = w[j] - t;
                    w[j] = w[j] + t;
                }
            }
        }

        w.into()
    }
}

// Algorithm 42 NTT^{−1}
impl NttPolynomial {
    pub fn ntt_inverse(&self) -> Polynomial {
        let mut w = self.0.clone();

        let mut m = 256;
        for len in [1, 2, 4, 8, 16, 32, 64, 128] {
            for start in (0..256).step_by(2 * len) {
                m -= 1;
                let z = -ZETA_POW_BITREV[m];

                for j in start..(start + len) {
                    let t = w[j];
                    w[j] = t + w[j + len];
                    w[j + len] = z * (t - w[j + len]);
                }
            }
        }

        FieldElement(8347681) * &Polynomial(w)
    }
}

/// A vector of K NTT-domain polynomials
#[derive(Clone, Default, Debug, PartialEq)]
pub struct NttVector<K: ArraySize>(pub Array<NttPolynomial, K>);

#[cfg(feature = "zeroize")]
impl<K> Zeroize for NttVector<K>
where
    K: ArraySize,
{
    fn zeroize(&mut self) {
        for poly in self.0.iter_mut() {
            poly.zeroize();
        }
    }
}

// Algorithm 46 AddVectorNTT
impl<K: ArraySize> Add<&NttVector<K>> for &NttVector<K> {
    type Output = NttVector<K>;

    fn add(self, rhs: &NttVector<K>) -> NttVector<K> {
        NttVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x + y)
                .collect(),
        )
    }
}

impl<K: ArraySize> Sub<&NttVector<K>> for &NttVector<K> {
    type Output = NttVector<K>;

    fn sub(self, rhs: &NttVector<K>) -> NttVector<K> {
        NttVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x - y)
                .collect(),
        )
    }
}

// Algorithm 47 ScalarVectorNTT
impl<K: ArraySize> Mul<&NttVector<K>> for &NttPolynomial {
    type Output = NttVector<K>;

    fn mul(self, rhs: &NttVector<K>) -> NttVector<K> {
        NttVector(rhs.0.iter().map(|x| self * x).collect())
    }
}

// Dot product of two polynomial vectors.  Used in MatrixVectorNTT.
//
// Incorporates:
// Algorithm 47 ScalarVectorNTT
impl<K: ArraySize> Mul<&NttVector<K>> for &NttVector<K> {
    type Output = NttPolynomial;

    fn mul(self, rhs: &NttVector<K>) -> NttPolynomial {
        self.0
            .iter()
            .zip(rhs.0.iter())
            .map(|(x, y)| x * y)
            .fold(NttPolynomial::default(), |x, y| &x + &y)
    }
}

impl<K: ArraySize> PolynomialVector<K> {
    pub fn ntt(&self) -> NttVector<K> {
        NttVector(self.0.iter().map(Polynomial::ntt).collect())
    }
}

impl<K: ArraySize> NttVector<K> {
    pub fn ntt_inverse(&self) -> PolynomialVector<K> {
        PolynomialVector(self.0.iter().map(NttPolynomial::ntt_inverse).collect())
    }
}

/// A K x L matrix of NTT-domain polynomials.  Each vector represents a row of the matrix, so that
/// multiplying on the right just requires iteration.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct NttMatrix<K: ArraySize, L: ArraySize>(Array<NttVector<L>, K>);

impl<K: ArraySize, L: ArraySize> Mul<&NttVector<L>> for &NttMatrix<K, L> {
    type Output = NttVector<K>;

    fn mul(self, rhs: &NttVector<L>) -> NttVector<K> {
        NttVector(self.0.iter().map(|x| x * rhs).collect())
    }
}

impl<K: ArraySize, L: ArraySize> NttMatrix<K, L> {
    // Algorithm 32 ExpandA
    pub fn expand_a(rho: &[u8]) -> Self {
        Self(Array::from_fn(|r| {
            NttVector(Array::from_fn(|s| {
                NttPolynomial::rej_ntt_poly(rho, r as u8, s as u8)
            }))
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hybrid_array::typenum::{U16, U2, U3};

    // Multiplication in R_q, modulo X^256 + 1
    impl Mul<&Polynomial> for &Polynomial {
        type Output = Polynomial;

        fn mul(self, rhs: &Polynomial) -> Self::Output {
            let mut out = Self::Output::default();
            for (i, x) in self.0.iter().enumerate() {
                for (j, y) in rhs.0.iter().enumerate() {
                    let (sign, index) = if i + j < 256 {
                        (FieldElement(1), i + j)
                    } else {
                        (FieldElement(FieldElement::Q - 1), i + j - 256)
                    };

                    out.0[index] = out.0[index] + (sign * *x * *y);
                }
            }
            out
        }
    }

    // A polynomial with only a scalar component, to make simple test cases
    fn const_ntt(x: Integer) -> NttPolynomial {
        let mut p = Polynomial::default();
        p.0[0] = FieldElement(x);
        p.ntt()
    }

    #[test]
    fn polynomial_ops() {
        let f = Polynomial(Array::from_fn(|i| FieldElement(i as Integer)));
        let g = Polynomial(Array::from_fn(|i| FieldElement(2 * i as Integer)));
        let sum = Polynomial(Array::from_fn(|i| FieldElement(3 * i as Integer)));
        assert_eq!((&f + &g), sum);
        assert_eq!((&sum - &g), f);
        assert_eq!(FieldElement(3) * &f, sum);
    }

    #[test]
    fn ntt() {
        let f = Polynomial(Array::from_fn(|i| FieldElement(i as Integer)));
        let g = Polynomial(Array::from_fn(|i| FieldElement(2 * i as Integer)));
        let f_hat = f.ntt();
        let g_hat = g.ntt();

        // Verify that NTT and NTT^-1 are actually inverses
        let f_unhat = f_hat.ntt_inverse();
        assert_eq!(f, f_unhat);

        // Verify that NTT is a homomorphism with regard to addition
        let fg = &f + &g;
        let f_hat_g_hat = &f_hat + &g_hat;
        let fg_unhat = f_hat_g_hat.ntt_inverse();
        assert_eq!(fg, fg_unhat);

        // Verify that NTT is a homomorphism with regard to multiplication
        let fg = &f * &g;
        let f_hat_g_hat = &f_hat * &g_hat;
        let fg_unhat = f_hat_g_hat.ntt_inverse();
        assert_eq!(fg, fg_unhat);
    }

    #[test]
    fn ntt_vector() {
        // Verify vector addition
        let v1: NttVector<U3> = NttVector(Array([const_ntt(1), const_ntt(1), const_ntt(1)]));
        let v2: NttVector<U3> = NttVector(Array([const_ntt(2), const_ntt(2), const_ntt(2)]));
        let v3: NttVector<U3> = NttVector(Array([const_ntt(3), const_ntt(3), const_ntt(3)]));
        assert_eq!((&v1 + &v2), v3);

        // Verify dot product
        assert_eq!((&v1 * &v2), const_ntt(6));
        assert_eq!((&v1 * &v3), const_ntt(9));
        assert_eq!((&v2 * &v3), const_ntt(18));
    }

    #[test]
    fn ntt_matrix() {
        // Verify matrix multiplication by a vector
        let a: NttMatrix<U3, U2> = NttMatrix(Array([
            NttVector(Array([const_ntt(1), const_ntt(2)])),
            NttVector(Array([const_ntt(3), const_ntt(4)])),
            NttVector(Array([const_ntt(5), const_ntt(6)])),
        ]));
        let v_in: NttVector<U2> = NttVector(Array([const_ntt(1), const_ntt(2)]));
        let v_out: NttVector<U3> = NttVector(Array([const_ntt(5), const_ntt(11), const_ntt(17)]));
        assert_eq!(&a * &v_in, v_out);
    }

    fn max_abs_1(p: Polynomial) -> bool {
        p.0.iter()
            .all(|x| x.0 == 0 || x.0 == 1 || x.0 == FieldElement::Q - 1)
    }

    fn hamming_weight(p: Polynomial) -> usize {
        p.0.iter().filter(|x| x.0 != 0).count()
    }

    // Verify that SampleInBall returns a polynomial with the following properties:
    //   a. All coefficients are from {-1, 0, 1}
    //   b. Hamming weight is exactly tau
    //
    // We test 256 samples for each value of
    #[test]
    fn sample_in_ball() {
        for tau in 1..65 {
            for seed in 0..255 {
                let rho = ((tau as u16) << 8) + (seed as u16);
                let p = Polynomial::sample_in_ball(&rho.to_be_bytes(), tau);
                assert_eq!(hamming_weight(p), tau);
                assert!(max_abs_1(p));
            }
        }
    }

    // Verify that RejNTTPoly produces samples that are in the proper range, and roughly uniform.
    // For the "roughly unform" criterion,
    #[test]
    fn rej_ntt_poly() {
        let sample: Array<Array<FieldElement, U256>, U16> = Array::from_fn(|i| {
            let i = i as u8;
            let rho = [i; 32];
            NttPolynomial::rej_ntt_poly(&rho, i, i + 1).into()
        });

        let sample = sample.as_flattened();

        let all_in_range = sample.iter().all(|x| x.0 < FieldElement::Q);
        assert!(all_in_range);

        // TODO measure uniformity
    }

    #[test]
    fn sample_cbd() {
        let rho = [0; 32];

        // Eta = 2
        let sample = Polynomial::rej_bounded_poly(&rho, Eta::Two, 0).0;
        let all_in_range = sample.iter().map(|x| *x + FieldElement(2)).all(|x| x.0 < 5);
        assert!(all_in_range);
        // TODO measure uniformity

        // Eta = 4
        let sample = Polynomial::rej_bounded_poly(&rho, Eta::Four, 0).0;
        let all_in_range = sample.iter().map(|x| *x + FieldElement(4)).all(|x| x.0 < 9);
        assert!(all_in_range);
        // TODO measure uniformity
    }
}
