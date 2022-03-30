use core::cmp::{Eq, PartialEq};

use subtle::Choice;
use subtle::ConditionallyNegatable;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use backend;
use constants;

#[cfg(feature = "fiat_u32_backend")]
pub use backend::serial::fiat_u32::field::*;
#[cfg(feature = "fiat_u64_backend")]
pub use backend::serial::fiat_u64::field::*;
#[cfg(feature = "fiat_u32_backend")]
pub type FieldElement = backend::serial::fiat_u32::field::FieldElement2625;
#[cfg(feature = "fiat_u64_backend")]
pub type FieldElement = backend::serial::fiat_u64::field::FieldElement51;

#[cfg(feature = "u64_backend")]
pub use backend::serial::u64::field::*;
#[cfg(feature = "u64_backend")]
pub type FieldElement = backend::serial::u64::field::FieldElement51;

#[cfg(feature = "u32_backend")]
pub use backend::serial::u32::field::*;
#[cfg(feature = "u32_backend")]
pub type FieldElement = backend::serial::u32::field::FieldElement2625;

impl Eq for FieldElement {}

impl PartialEq for FieldElement {
    fn eq(&self, other: &FieldElement) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &FieldElement) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl FieldElement {
    pub fn is_negative(&self) -> Choice {
        let bytes = self.to_bytes();
        (bytes[0] & 1).into()
    }

    pub fn is_zero(&self) -> Choice {
        let zero = [0u8; 32];
        let bytes = self.to_bytes();

        bytes.ct_eq(&zero)
    }

    fn pow22501(&self) -> (FieldElement, FieldElement) {
        let t0 = self.square();
        let t1 = t0.square().square();
        let t2 = self * &t1;
        let t3 = &t0 * &t2;
        let t4 = t3.square();
        let t5 = &t2 * &t4;
        let t6 = t5.pow2k(5);
        let t7 = &t6 * &t5;
        let t8 = t7.pow2k(10);
        let t9 = &t8 * &t7;
        let t10 = t9.pow2k(20);
        let t11 = &t10 * &t9;
        let t12 = t11.pow2k(10);
        let t13 = &t12 * &t7;
        let t14 = t13.pow2k(50);
        let t15 = &t14 * &t13;
        let t16 = t15.pow2k(100);
        let t17 = &t16 * &t15;
        let t18 = t17.pow2k(50);
        let t19 = &t18 * &t13;

        (t19, t3)
    }

    #[cfg(feature = "alloc")]
    pub fn batch_invert(inputs: &mut [FieldElement]) {
        let n = inputs.len();
        let mut scratch = vec![FieldElement::one(); n];

        let mut acc = FieldElement::one();

        for (input, scratch) in inputs.iter().zip(scratch.iter_mut()) {
            *scratch = acc;
            acc = &acc * input;
        }

        assert_eq!(acc.is_zero().unwrap_u8(), 0);

        acc = acc.invert();

        for (input, scratch) in inputs.iter_mut().rev().zip(scratch.into_iter().rev()) {
            let tmp = &acc * input;
            *input = &acc * &scratch;
            acc = tmp;
        }
    }

    pub fn invert(&self) -> FieldElement {
        let (t19, t3) = self.pow22501();
        let t20 = t19.pow2k(5);
        let t21 = &t20 * &t3;

        t21
    }

    fn pow_p58(&self) -> FieldElement {
        let (t19, _) = self.pow22501();
        let t20 = t19.pow2k(2);
        let t21 = self * &t20;

        t21
    }

    pub fn sqrt_ratio_i(u: &FieldElement, v: &FieldElement) -> (Choice, FieldElement) {
        let v3 = &v.square() * v;
        let v7 = &v3.square() * v;
        let mut r = &(u * &v3) * &(u * &v7).pow_p58();
        let check = v * &r.square();

        let i = &constants::SQRT_M1;

        let correct_sign_sqrt = check.ct_eq(u);
        let flipped_sign_sqrt = check.ct_eq(&(-u));
        let flipped_sign_sqrt_i = check.ct_eq(&(&(-u) * i));

        let r_prime = &constants::SQRT_M1 * &r;
        r.conditional_assign(&r_prime, flipped_sign_sqrt | flipped_sign_sqrt_i);

        let r_is_negative = r.is_negative();
        r.conditional_negate(r_is_negative);

        let was_nonzero_square = correct_sign_sqrt | flipped_sign_sqrt;

        (was_nonzero_square, r)
    }

    pub fn invsqrt(&self) -> (Choice, FieldElement) {
        FieldElement::sqrt_ratio_i(&FieldElement::one(), self)
    }
}

#[cfg(test)]
mod test {
    use field::*;
    use subtle::ConditionallyNegatable;

    static A_BYTES: [u8; 32] = [
        0x04, 0xfe, 0xdf, 0x98, 0xa7, 0xfa, 0x0a, 0x68, 0x84, 0x92, 0xbd, 0x59, 0x08, 0x07, 0xa7,
        0x03, 0x9e, 0xd1, 0xf6, 0xf2, 0xe1, 0xd9, 0xe2, 0xa4, 0xa4, 0x51, 0x47, 0x36, 0xf3, 0xc3,
        0xa9, 0x17,
    ];

    static ASQ_BYTES: [u8; 32] = [
        0x75, 0x97, 0x24, 0x9e, 0xe6, 0x06, 0xfe, 0xab, 0x24, 0x04, 0x56, 0x68, 0x07, 0x91, 0x2d,
        0x5d, 0x0b, 0x0f, 0x3f, 0x1c, 0xb2, 0x6e, 0xf2, 0xe2, 0x63, 0x9c, 0x12, 0xba, 0x73, 0x0b,
        0xe3, 0x62,
    ];

    static AINV_BYTES: [u8; 32] = [
        0x96, 0x1b, 0xcd, 0x8d, 0x4d, 0x5e, 0xa2, 0x3a, 0xe9, 0x36, 0x37, 0x93, 0xdb, 0x7b, 0x4d,
        0x70, 0xb8, 0x0d, 0xc0, 0x55, 0xd0, 0x4c, 0x1d, 0x7b, 0x90, 0x71, 0xd8, 0xe9, 0xb6, 0x18,
        0xe6, 0x30,
    ];

    static AP58_BYTES: [u8; 32] = [
        0x6a, 0x4f, 0x24, 0x89, 0x1f, 0x57, 0x60, 0x36, 0xd0, 0xbe, 0x12, 0x3c, 0x8f, 0xf5, 0xb1,
        0x59, 0xe0, 0xf0, 0xb8, 0x1b, 0x20, 0xd2, 0xb5, 0x1f, 0x15, 0x21, 0xf9, 0xe3, 0xe1, 0x61,
        0x21, 0x55,
    ];

    #[test]
    fn a_mul_a_vs_a_squared_constant() {
        let a = FieldElement::from_bytes(&A_BYTES);
        let asq = FieldElement::from_bytes(&ASQ_BYTES);
        assert_eq!(asq, &a * &a);
    }

    #[test]
    fn a_square_vs_a_squared_constant() {
        let a = FieldElement::from_bytes(&A_BYTES);
        let asq = FieldElement::from_bytes(&ASQ_BYTES);
        assert_eq!(asq, a.square());
    }

    #[test]
    fn a_square2_vs_a_squared_constant() {
        let a = FieldElement::from_bytes(&A_BYTES);
        let asq = FieldElement::from_bytes(&ASQ_BYTES);
        assert_eq!(a.square2(), &asq + &asq);
    }

    #[test]
    fn a_invert_vs_inverse_of_a_constant() {
        let a = FieldElement::from_bytes(&A_BYTES);
        let ainv = FieldElement::from_bytes(&AINV_BYTES);
        let should_be_inverse = a.invert();
        assert_eq!(ainv, should_be_inverse);
        assert_eq!(FieldElement::one(), &a * &should_be_inverse);
    }

    #[test]
    fn batch_invert_a_matches_nonbatched() {
        let a = FieldElement::from_bytes(&A_BYTES);
        let ap58 = FieldElement::from_bytes(&AP58_BYTES);
        let asq = FieldElement::from_bytes(&ASQ_BYTES);
        let ainv = FieldElement::from_bytes(&AINV_BYTES);
        let a2 = &a + &a;
        let a_list = vec![a, ap58, asq, ainv, a2];
        let mut ainv_list = a_list.clone();
        FieldElement::batch_invert(&mut ainv_list[..]);
        for i in 0..5 {
            assert_eq!(a_list[i].invert(), ainv_list[i]);
        }
    }

    #[test]
    fn sqrt_ratio_behavior() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        let i = constants::SQRT_M1;
        let two = &one + &one;
        let four = &two + &two;

        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&zero, &zero);
        assert_eq!(choice.unwrap_u8(), 1);
        assert_eq!(sqrt, zero);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&one, &zero);
        assert_eq!(choice.unwrap_u8(), 0);
        assert_eq!(sqrt, zero);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&two, &one);
        assert_eq!(choice.unwrap_u8(), 0);
        assert_eq!(sqrt.square(), &two * &i);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&four, &one);
        assert_eq!(choice.unwrap_u8(), 1);
        assert_eq!(sqrt.square(), four);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&one, &four);
        assert_eq!(choice.unwrap_u8(), 1);
        assert_eq!(&sqrt.square() * &four, one);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);
    }

    #[test]
    fn a_p58_vs_ap58_constant() {
        let a = FieldElement::from_bytes(&A_BYTES);
        let ap58 = FieldElement::from_bytes(&AP58_BYTES);
        assert_eq!(ap58, a.pow_p58());
    }

    #[test]
    fn equality() {
        let a = FieldElement::from_bytes(&A_BYTES);
        let ainv = FieldElement::from_bytes(&AINV_BYTES);
        assert!(a == a);
        assert!(a != ainv);
    }

    static B_BYTES: [u8; 32] = [
        113, 191, 169, 143, 91, 234, 121, 15, 241, 131, 217, 36, 230, 101, 92, 234, 8, 208, 170,
        251, 97, 127, 70, 210, 58, 23, 166, 87, 240, 169, 184, 178,
    ];

    #[test]
    fn from_bytes_highbit_is_ignored() {
        let mut cleared_bytes = B_BYTES;
        cleared_bytes[31] &= 127u8;
        let with_highbit_set = FieldElement::from_bytes(&B_BYTES);
        let without_highbit_set = FieldElement::from_bytes(&cleared_bytes);
        assert_eq!(without_highbit_set, with_highbit_set);
    }

    #[test]
    fn conditional_negate() {
        let one = FieldElement::one();
        let minus_one = FieldElement::minus_one();
        let mut x = one;
        x.conditional_negate(Choice::from(1));
        assert_eq!(x, minus_one);
        x.conditional_negate(Choice::from(0));
        assert_eq!(x, minus_one);
        x.conditional_negate(Choice::from(1));
        assert_eq!(x, one);
    }

    #[test]
    fn encoding_is_canonical() {
        let one_encoded_wrongly_bytes: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let one = FieldElement::from_bytes(&one_encoded_wrongly_bytes);
        let one_bytes = one.to_bytes();
        assert_eq!(one_bytes[0], 1);
        for i in 1..32 {
            assert_eq!(one_bytes[i], 0);
        }
    }

    #[test]
    fn batch_invert_empty() {
        FieldElement::batch_invert(&mut []);
    }
}
