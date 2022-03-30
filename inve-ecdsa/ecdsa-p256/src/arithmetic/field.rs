#![allow(clippy::assign_op_pattern, clippy::op_ref)]

use crate::{
    arithmetic::util::{adc, mac, sbb},
    FieldBytes,
};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    ff::Field,
    rand_core::RngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
};

const LIMBS: usize = 4;

pub const MODULUS: FieldElement = FieldElement([
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]);

const R: FieldElement = FieldElement([
    0x0000_0000_0000_0001,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_fffe,
]);

const R2: FieldElement = FieldElement([
    0x0000_0000_0000_0003,
    0xffff_fffb_ffff_ffff,
    0xffff_ffff_ffff_fffe,
    0x0000_0004_ffff_fffd,
]);

#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(crate) [u64; LIMBS]);

impl Field for FieldElement {
    fn random(mut rng: impl RngCore) -> Self {
        let mut buf = [0; 64];
        rng.fill_bytes(&mut buf);
        FieldElement::from_bytes_wide(buf)
    }

    fn zero() -> Self {
        Self::ZERO
    }

    fn one() -> Self {
        Self::ONE
    }

    #[must_use]
    fn square(&self) -> Self {
        self.square()
    }

    #[must_use]
    fn double(&self) -> Self {
        self.double()
    }

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }

    fn sqrt(&self) -> CtOption<Self> {
        self.sqrt()
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &FieldElement, b: &FieldElement, choice: Choice) -> FieldElement {
        FieldElement([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        FieldElement::zero()
    }
}

impl DefaultIsZeroes for FieldElement {}

impl Eq for FieldElement {}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl FieldElement {
    pub const ZERO: Self = FieldElement([0, 0, 0, 0]);

    pub const ONE: Self = R;

    fn from_bytes_wide(bytes: [u8; 64]) -> Self {
        FieldElement::montgomery_reduce(
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
            u64::from_be_bytes(bytes[40..48].try_into().unwrap()),
            u64::from_be_bytes(bytes[48..56].try_into().unwrap()),
            u64::from_be_bytes(bytes[56..64].try_into().unwrap()),
        )
    }

    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
        let mut w = [0u64; LIMBS];

        w[3] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        w[2] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        w[1] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        w[0] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());

        let (_, borrow) = sbb(w[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb(w[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb(w[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(w[3], MODULUS.0[3], borrow);
        let is_some = (borrow as u8) & 1;

        CtOption::new(FieldElement(w).to_montgomery(), Choice::from(is_some))
    }

    pub fn to_bytes(self) -> FieldBytes {
        let tmp = self.to_canonical();

        let mut ret = FieldBytes::default();
        ret[0..8].copy_from_slice(&tmp.0[3].to_be_bytes());
        ret[8..16].copy_from_slice(&tmp.0[2].to_be_bytes());
        ret[16..24].copy_from_slice(&tmp.0[1].to_be_bytes());
        ret[24..32].copy_from_slice(&tmp.0[0].to_be_bytes());
        ret
    }

    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&FieldElement::zero())
    }

    pub fn is_odd(&self) -> Choice {
        let bytes = self.to_bytes();
        (bytes[31] & 1).into()
    }

    pub const fn add(&self, rhs: &Self) -> Self {
        let (w0, carry) = adc(self.0[0], rhs.0[0], 0);
        let (w1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (w2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (w3, w4) = adc(self.0[3], rhs.0[3], carry);

        let (result, _) = Self::sub_inner(
            w0,
            w1,
            w2,
            w3,
            w4,
            MODULUS.0[0],
            MODULUS.0[1],
            MODULUS.0[2],
            MODULUS.0[3],
            0,
        );
        result
    }

    pub const fn double(&self) -> Self {
        self.add(self)
    }

    pub const fn subtract(&self, rhs: &Self) -> Self {
        let (result, _) = Self::sub_inner(
            self.0[0], self.0[1], self.0[2], self.0[3], 0, rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3],
            0,
        );
        result
    }

    pub(crate) const fn informed_subtract(&self, rhs: &Self) -> (Self, u64) {
        Self::sub_inner(
            self.0[0], self.0[1], self.0[2], self.0[3], 0, rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3],
            0,
        )
    }
    #[inline]
    #[allow(clippy::too_many_arguments)]
    const fn sub_inner(
        l0: u64,
        l1: u64,
        l2: u64,
        l3: u64,
        l4: u64,
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
    ) -> (Self, u64) {
        let (w0, borrow) = sbb(l0, r0, 0);
        let (w1, borrow) = sbb(l1, r1, borrow);
        let (w2, borrow) = sbb(l2, r2, borrow);
        let (w3, borrow) = sbb(l3, r3, borrow);
        let (_, borrow) = sbb(l4, r4, borrow);

        let (w0, carry) = adc(w0, MODULUS.0[0] & borrow, 0);
        let (w1, carry) = adc(w1, MODULUS.0[1] & borrow, carry);
        let (w2, carry) = adc(w2, MODULUS.0[2] & borrow, carry);
        let (w3, _) = adc(w3, MODULUS.0[3] & borrow, carry);

        (FieldElement([w0, w1, w2, w3]), borrow)
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    const fn montgomery_reduce(
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
        r6: u64,
        r7: u64,
    ) -> Self {
        let (r1, carry) = mac(r1, r0, MODULUS.0[1], r0);
        let (r2, carry) = adc(r2, 0, carry);
        let (r3, carry) = mac(r3, r0, MODULUS.0[3], carry);
        let (r4, carry2) = adc(r4, 0, carry);

        let (r2, carry) = mac(r2, r1, MODULUS.0[1], r1);
        let (r3, carry) = adc(r3, 0, carry);
        let (r4, carry) = mac(r4, r1, MODULUS.0[3], carry);
        let (r5, carry2) = adc(r5, carry2, carry);

        let (r3, carry) = mac(r3, r2, MODULUS.0[1], r2);
        let (r4, carry) = adc(r4, 0, carry);
        let (r5, carry) = mac(r5, r2, MODULUS.0[3], carry);
        let (r6, carry2) = adc(r6, carry2, carry);

        let (r4, carry) = mac(r4, r3, MODULUS.0[1], r3);
        let (r5, carry) = adc(r5, 0, carry);
        let (r6, carry) = mac(r6, r3, MODULUS.0[3], carry);
        let (r7, r8) = adc(r7, carry2, carry);

        let (result, _) = Self::sub_inner(
            r4,
            r5,
            r6,
            r7,
            r8,
            MODULUS.0[0],
            MODULUS.0[1],
            MODULUS.0[2],
            MODULUS.0[3],
            0,
        );
        result
    }

    #[inline]
    pub(crate) const fn to_canonical(self) -> Self {
        FieldElement::montgomery_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0)
    }

    #[inline]
    pub(crate) const fn to_montgomery(self) -> Self {
        Self::mul(&self, &R2)
    }

    pub const fn mul(&self, rhs: &Self) -> Self {
        let (w0, carry) = mac(0, self.0[0], rhs.0[0], 0);
        let (w1, carry) = mac(0, self.0[0], rhs.0[1], carry);
        let (w2, carry) = mac(0, self.0[0], rhs.0[2], carry);
        let (w3, w4) = mac(0, self.0[0], rhs.0[3], carry);

        let (w1, carry) = mac(w1, self.0[1], rhs.0[0], 0);
        let (w2, carry) = mac(w2, self.0[1], rhs.0[1], carry);
        let (w3, carry) = mac(w3, self.0[1], rhs.0[2], carry);
        let (w4, w5) = mac(w4, self.0[1], rhs.0[3], carry);

        let (w2, carry) = mac(w2, self.0[2], rhs.0[0], 0);
        let (w3, carry) = mac(w3, self.0[2], rhs.0[1], carry);
        let (w4, carry) = mac(w4, self.0[2], rhs.0[2], carry);
        let (w5, w6) = mac(w5, self.0[2], rhs.0[3], carry);

        let (w3, carry) = mac(w3, self.0[3], rhs.0[0], 0);
        let (w4, carry) = mac(w4, self.0[3], rhs.0[1], carry);
        let (w5, carry) = mac(w5, self.0[3], rhs.0[2], carry);
        let (w6, w7) = mac(w6, self.0[3], rhs.0[3], carry);

        FieldElement::montgomery_reduce(w0, w1, w2, w3, w4, w5, w6, w7)
    }

    pub const fn square(&self) -> Self {
        self.mul(self)
    }

    pub fn pow_vartime(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();

                if ((*e >> i) & 1) == 1 {
                    res = res * self;
                }
            }
        }
        res
    }

    pub fn invert(&self) -> CtOption<Self> {
        let inverse = self.pow_vartime(&[
            0xffff_ffff_ffff_fffd,
            0x0000_0000_ffff_ffff,
            0x0000_0000_0000_0000,
            0xffff_ffff_0000_0001,
        ]);

        CtOption::new(inverse, !self.is_zero())
    }

    pub fn sqrt(&self) -> CtOption<Self> {
        let sqrt = self.pow_vartime(&[
            0x0000_0000_0000_0000,
            0x0000_0000_4000_0000,
            0x4000_0000_0000_0000,
            0x3fff_ffff_c000_0000,
        ]);

        CtOption::new(sqrt, (&sqrt * &sqrt).ct_eq(self))
    }
}

impl Add<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: FieldElement) -> FieldElement {
        FieldElement::add(&self, &other)
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement::add(&self, other)
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement::add(self, other)
    }
}

impl AddAssign<FieldElement> for FieldElement {
    fn add_assign(&mut self, other: FieldElement) {
        *self = FieldElement::add(self, &other);
    }
}

impl AddAssign<&FieldElement> for FieldElement {
    fn add_assign(&mut self, other: &FieldElement) {
        *self = FieldElement::add(self, other);
    }
}

impl Sub<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: FieldElement) -> FieldElement {
        FieldElement::subtract(&self, &other)
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        FieldElement::subtract(&self, other)
    }
}

impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        FieldElement::subtract(self, other)
    }
}

impl SubAssign<FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: FieldElement) {
        *self = FieldElement::subtract(self, &other);
    }
}

impl SubAssign<&FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: &FieldElement) {
        *self = FieldElement::subtract(self, other);
    }
}

impl Mul<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: FieldElement) -> FieldElement {
        FieldElement::mul(&self, &other)
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement::mul(&self, other)
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement::mul(self, other)
    }
}

impl MulAssign<FieldElement> for FieldElement {
    fn mul_assign(&mut self, other: FieldElement) {
        *self = FieldElement::mul(self, &other);
    }
}

impl MulAssign<&FieldElement> for FieldElement {
    fn mul_assign(&mut self, other: &FieldElement) {
        *self = FieldElement::mul(self, other);
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement::zero() - &self
    }
}

impl Neg for &FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement::zero() - self
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement;
    use crate::{test_vectors::field::DBL_TEST_VECTORS, FieldBytes};
    use elliptic_curve::ff::Field;
    use proptest::{num::u64::ANY, prelude::*};

    #[test]
    fn zero_is_additive_identity() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        assert_eq!(zero.add(&zero), zero);
        assert_eq!(one.add(&zero), one);
    }

    #[test]
    fn one_is_multiplicative_identity() {
        let one = FieldElement::one();
        assert_eq!(one.mul(&one), one);
    }

    #[test]
    fn from_bytes() {
        assert_eq!(
            FieldElement::from_bytes(&FieldBytes::default()).unwrap(),
            FieldElement::zero()
        );
        assert_eq!(
            FieldElement::from_bytes(
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 1
                ]
                .into()
            )
            .unwrap(),
            FieldElement::one()
        );
        assert!(bool::from(
            FieldElement::from_bytes(&[0xff; 32].into()).is_none()
        ));
    }

    #[test]
    fn to_bytes() {
        assert_eq!(FieldElement::zero().to_bytes(), FieldBytes::default());
        assert_eq!(
            FieldElement::one().to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ]
            .into()
        );
    }

    #[test]
    fn repeated_add() {
        let mut r = FieldElement::one();
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.to_bytes(), DBL_TEST_VECTORS[i].into());
            r = r + &r;
        }
    }

    #[test]
    fn repeated_double() {
        let mut r = FieldElement::one();
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.to_bytes(), DBL_TEST_VECTORS[i].into());
            r = r.double();
        }
    }

    #[test]
    fn repeated_mul() {
        let mut r = FieldElement::one();
        let two = r + &r;
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.to_bytes(), DBL_TEST_VECTORS[i].into());
            r = r * &two;
        }
    }

    #[test]
    fn negation() {
        let two = FieldElement::one().double();
        let neg_two = -two;
        assert_eq!(two + &neg_two, FieldElement::zero());
        assert_eq!(-neg_two, two);
    }

    #[test]
    fn pow_vartime() {
        let one = FieldElement::one();
        let two = one + &one;
        let four = two.square();
        assert_eq!(two.pow_vartime(&[2, 0, 0, 0]), four);
    }

    #[test]
    fn invert() {
        assert!(bool::from(FieldElement::zero().invert().is_none()));

        let one = FieldElement::one();
        assert_eq!(one.invert().unwrap(), one);

        let two = one + &one;
        let inv_two = two.invert().unwrap();
        assert_eq!(two * &inv_two, one);
    }

    #[test]
    fn sqrt() {
        let one = FieldElement::one();
        let two = one + &one;
        let four = two.square();
        assert_eq!(four.sqrt().unwrap(), two);
    }

    proptest! {
        #[test]
        fn add_then_sub(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
            b0 in ANY,
            b1 in ANY,
            b2 in ANY,
        ) {
            let a = FieldElement([a0, a1, a2, 0]);
            let b = FieldElement([b0, b1, b2, 0]);
            assert_eq!(a.add(&b).subtract(&a), b);
        }
    }
}
