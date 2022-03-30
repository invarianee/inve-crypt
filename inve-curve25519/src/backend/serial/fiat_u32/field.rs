use core::fmt::Debug;
use core::ops::Neg;
use core::ops::{Add, AddAssign};
use core::ops::{Mul, MulAssign};
use core::ops::{Sub, SubAssign};

use subtle::Choice;
use subtle::ConditionallySelectable;

use zeroize::Zeroize;

use fiat_crypto::curve25519_32::*;

#[derive(Copy, Clone)]
pub struct FieldElement2625(pub(crate) [u32; 10]);

impl Debug for FieldElement2625 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "FieldElement2625({:?})", &self.0[..])
    }
}

impl Zeroize for FieldElement2625 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<'b> AddAssign<&'b FieldElement2625> for FieldElement2625 {
    fn add_assign(&mut self, _rhs: &'b FieldElement2625) {
        let input = self.0;
        fiat_25519_add(&mut self.0, &input, &_rhs.0);
        let input = self.0;
        fiat_25519_carry(&mut self.0, &input);
    }
}

impl<'a, 'b> Add<&'b FieldElement2625> for &'a FieldElement2625 {
    type Output = FieldElement2625;
    fn add(self, _rhs: &'b FieldElement2625) -> FieldElement2625 {
        let mut output = *self;
        fiat_25519_add(&mut output.0, &self.0, &_rhs.0);
        let input = output.0;
        fiat_25519_carry(&mut output.0, &input);
        output
    }
}

impl<'b> SubAssign<&'b FieldElement2625> for FieldElement2625 {
    fn sub_assign(&mut self, _rhs: &'b FieldElement2625) {
        let input = self.0;
        fiat_25519_sub(&mut self.0, &input, &_rhs.0);
        let input = self.0;
        fiat_25519_carry(&mut self.0, &input);
    }
}

impl<'a, 'b> Sub<&'b FieldElement2625> for &'a FieldElement2625 {
    type Output = FieldElement2625;
    fn sub(self, _rhs: &'b FieldElement2625) -> FieldElement2625 {
        let mut output = *self;
        fiat_25519_sub(&mut output.0, &self.0, &_rhs.0);
        let input = output.0;
        fiat_25519_carry(&mut output.0, &input);
        output
    }
}

impl<'b> MulAssign<&'b FieldElement2625> for FieldElement2625 {
    fn mul_assign(&mut self, _rhs: &'b FieldElement2625) {
        let input = self.0;
        fiat_25519_carry_mul(&mut self.0, &input, &_rhs.0);
    }
}

impl<'a, 'b> Mul<&'b FieldElement2625> for &'a FieldElement2625 {
    type Output = FieldElement2625;
    fn mul(self, _rhs: &'b FieldElement2625) -> FieldElement2625 {
        let mut output = *self;
        fiat_25519_carry_mul(&mut output.0, &self.0, &_rhs.0);
        output
    }
}

impl<'a> Neg for &'a FieldElement2625 {
    type Output = FieldElement2625;
    fn neg(self) -> FieldElement2625 {
        let mut output = *self;
        fiat_25519_opp(&mut output.0, &self.0);
        let input = output.0;
        fiat_25519_carry(&mut output.0, &input);
        output
    }
}

impl ConditionallySelectable for FieldElement2625 {
    fn conditional_select(
        a: &FieldElement2625,
        b: &FieldElement2625,
        choice: Choice,
    ) -> FieldElement2625 {
        let mut output = [0u32; 10];
        fiat_25519_selectznz(&mut output, choice.unwrap_u8() as fiat_25519_u1, &a.0, &b.0);
        FieldElement2625(output)
    }

    fn conditional_assign(&mut self, other: &FieldElement2625, choice: Choice) {
        let mut output = [0u32; 10];
        let choicebit = choice.unwrap_u8() as fiat_25519_u1;
        fiat_25519_cmovznz_u32(&mut output[0], choicebit, self.0[0], other.0[0]);
        fiat_25519_cmovznz_u32(&mut output[1], choicebit, self.0[1], other.0[1]);
        fiat_25519_cmovznz_u32(&mut output[2], choicebit, self.0[2], other.0[2]);
        fiat_25519_cmovznz_u32(&mut output[3], choicebit, self.0[3], other.0[3]);
        fiat_25519_cmovznz_u32(&mut output[4], choicebit, self.0[4], other.0[4]);
        fiat_25519_cmovznz_u32(&mut output[5], choicebit, self.0[5], other.0[5]);
        fiat_25519_cmovznz_u32(&mut output[6], choicebit, self.0[6], other.0[6]);
        fiat_25519_cmovznz_u32(&mut output[7], choicebit, self.0[7], other.0[7]);
        fiat_25519_cmovznz_u32(&mut output[8], choicebit, self.0[8], other.0[8]);
        fiat_25519_cmovznz_u32(&mut output[9], choicebit, self.0[9], other.0[9]);
        *self = FieldElement2625(output);
    }

    fn conditional_swap(a: &mut FieldElement2625, b: &mut FieldElement2625, choice: Choice) {
        u32::conditional_swap(&mut a.0[0], &mut b.0[0], choice);
        u32::conditional_swap(&mut a.0[1], &mut b.0[1], choice);
        u32::conditional_swap(&mut a.0[2], &mut b.0[2], choice);
        u32::conditional_swap(&mut a.0[3], &mut b.0[3], choice);
        u32::conditional_swap(&mut a.0[4], &mut b.0[4], choice);
        u32::conditional_swap(&mut a.0[5], &mut b.0[5], choice);
        u32::conditional_swap(&mut a.0[6], &mut b.0[6], choice);
        u32::conditional_swap(&mut a.0[7], &mut b.0[7], choice);
        u32::conditional_swap(&mut a.0[8], &mut b.0[8], choice);
        u32::conditional_swap(&mut a.0[9], &mut b.0[9], choice);
    }
}

impl FieldElement2625 {
    pub fn negate(&mut self) {
        let neg = self.neg();
        self.0 = neg.0;
    }

    pub fn zero() -> FieldElement2625 {
        FieldElement2625([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    pub fn one() -> FieldElement2625 {
        FieldElement2625([1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    pub fn minus_one() -> FieldElement2625 {
        FieldElement2625([
            0x3ffffec, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff,
            0x3ffffff, 0x1ffffff,
        ])
    }

    pub fn pow2k(&self, k: u32) -> FieldElement2625 {
        debug_assert!(k > 0);
        let mut z = self.square();
        for _ in 1..k {
            z = z.square();
        }
        z
    }

    pub fn from_bytes(data: &[u8; 32]) -> FieldElement2625 {
        let mut temp = [0u8; 32];
        temp.copy_from_slice(data);
        temp[31] &= 127u8;
        let mut output = [0u32; 10];
        fiat_25519_from_bytes(&mut output, &temp);
        FieldElement2625(output)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        fiat_25519_to_bytes(&mut bytes, &self.0);
        return bytes;
    }

    pub fn square(&self) -> FieldElement2625 {
        let mut output = *self;
        fiat_25519_carry_square(&mut output.0, &self.0);
        output
    }

    pub fn square2(&self) -> FieldElement2625 {
        let mut output = *self;
        let mut temp = *self;
        fiat_25519_carry_square(&mut temp.0, &self.0);
        fiat_25519_add(&mut output.0, &temp.0, &temp.0);
        let input = output.0;
        fiat_25519_carry(&mut output.0, &input);
        output
    }
}
