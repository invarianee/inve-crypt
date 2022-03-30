use core::fmt::Debug;
use core::ops::Neg;
use core::ops::{Add, AddAssign};
use core::ops::{Mul, MulAssign};
use core::ops::{Sub, SubAssign};

use subtle::Choice;
use subtle::ConditionallySelectable;

use zeroize::Zeroize;

use fiat_crypto::curve25519_64::*;

#[derive(Copy, Clone)]
pub struct FieldElement51(pub(crate) [u64; 5]);

impl Debug for FieldElement51 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "FieldElement51({:?})", &self.0[..])
    }
}

impl Zeroize for FieldElement51 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<'b> AddAssign<&'b FieldElement51> for FieldElement51 {
    fn add_assign(&mut self, _rhs: &'b FieldElement51) {
        let input = self.0;
        fiat_25519_add(&mut self.0, &input, &_rhs.0);
        let input = self.0;
        fiat_25519_carry(&mut self.0, &input);
    }
}

impl<'a, 'b> Add<&'b FieldElement51> for &'a FieldElement51 {
    type Output = FieldElement51;
    fn add(self, _rhs: &'b FieldElement51) -> FieldElement51 {
        let mut output = *self;
        fiat_25519_add(&mut output.0, &self.0, &_rhs.0);
        let input = output.0;
        fiat_25519_carry(&mut output.0, &input);
        output
    }
}

impl<'b> SubAssign<&'b FieldElement51> for FieldElement51 {
    fn sub_assign(&mut self, _rhs: &'b FieldElement51) {
        let input = self.0;
        fiat_25519_sub(&mut self.0, &input, &_rhs.0);
        let input = self.0;
        fiat_25519_carry(&mut self.0, &input);
    }
}

impl<'a, 'b> Sub<&'b FieldElement51> for &'a FieldElement51 {
    type Output = FieldElement51;
    fn sub(self, _rhs: &'b FieldElement51) -> FieldElement51 {
        let mut output = *self;
        fiat_25519_sub(&mut output.0, &self.0, &_rhs.0);
        let input = output.0;
        fiat_25519_carry(&mut output.0, &input);
        output
    }
}

impl<'b> MulAssign<&'b FieldElement51> for FieldElement51 {
    fn mul_assign(&mut self, _rhs: &'b FieldElement51) {
        let input = self.0;
        fiat_25519_carry_mul(&mut self.0, &input, &_rhs.0);
    }
}

impl<'a, 'b> Mul<&'b FieldElement51> for &'a FieldElement51 {
    type Output = FieldElement51;
    fn mul(self, _rhs: &'b FieldElement51) -> FieldElement51 {
        let mut output = *self;
        fiat_25519_carry_mul(&mut output.0, &self.0, &_rhs.0);
        output
    }
}

impl<'a> Neg for &'a FieldElement51 {
    type Output = FieldElement51;
    fn neg(self) -> FieldElement51 {
        let mut output = *self;
        fiat_25519_opp(&mut output.0, &self.0);
        let input = output.0;
        fiat_25519_carry(&mut output.0, &input);
        output
    }
}

impl ConditionallySelectable for FieldElement51 {
    fn conditional_select(
        a: &FieldElement51,
        b: &FieldElement51,
        choice: Choice,
    ) -> FieldElement51 {
        let mut output = [0u64; 5];
        fiat_25519_selectznz(&mut output, choice.unwrap_u8() as fiat_25519_u1, &a.0, &b.0);
        FieldElement51(output)
    }

    fn conditional_swap(a: &mut FieldElement51, b: &mut FieldElement51, choice: Choice) {
        u64::conditional_swap(&mut a.0[0], &mut b.0[0], choice);
        u64::conditional_swap(&mut a.0[1], &mut b.0[1], choice);
        u64::conditional_swap(&mut a.0[2], &mut b.0[2], choice);
        u64::conditional_swap(&mut a.0[3], &mut b.0[3], choice);
        u64::conditional_swap(&mut a.0[4], &mut b.0[4], choice);
    }

    fn conditional_assign(&mut self, _rhs: &FieldElement51, choice: Choice) {
        let mut output = [0u64; 5];
        let choicebit = choice.unwrap_u8() as fiat_25519_u1;
        fiat_25519_cmovznz_u64(&mut output[0], choicebit, self.0[0], _rhs.0[0]);
        fiat_25519_cmovznz_u64(&mut output[1], choicebit, self.0[1], _rhs.0[1]);
        fiat_25519_cmovznz_u64(&mut output[2], choicebit, self.0[2], _rhs.0[2]);
        fiat_25519_cmovznz_u64(&mut output[3], choicebit, self.0[3], _rhs.0[3]);
        fiat_25519_cmovznz_u64(&mut output[4], choicebit, self.0[4], _rhs.0[4]);
        *self = FieldElement51(output);
    }
}

impl FieldElement51 {
    pub fn zero() -> FieldElement51 {
        FieldElement51([0, 0, 0, 0, 0])
    }

    pub fn one() -> FieldElement51 {
        FieldElement51([1, 0, 0, 0, 0])
    }

    pub fn minus_one() -> FieldElement51 {
        FieldElement51([
            2251799813685228,
            2251799813685247,
            2251799813685247,
            2251799813685247,
            2251799813685247,
        ])
    }

    #[inline(always)]
    #[allow(dead_code)]
    fn reduce(mut limbs: [u64; 5]) -> FieldElement51 {
        let input = limbs;
        fiat_25519_carry(&mut limbs, &input);
        FieldElement51(limbs)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> FieldElement51 {
        let mut temp = [0u8; 32];
        temp.copy_from_slice(bytes);
        temp[31] &= 127u8;
        let mut output = [0u64; 5];
        fiat_25519_from_bytes(&mut output, &temp);
        FieldElement51(output)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        fiat_25519_to_bytes(&mut bytes, &self.0);
        return bytes;
    }

    pub fn pow2k(&self, mut k: u32) -> FieldElement51 {
        let mut output = *self;
        loop {
            let input = output.0;
            fiat_25519_carry_square(&mut output.0, &input);
            k -= 1;
            if k == 0 {
                return output;
            }
        }
    }

    pub fn square(&self) -> FieldElement51 {
        let mut output = *self;
        fiat_25519_carry_square(&mut output.0, &self.0);
        output
    }

    pub fn square2(&self) -> FieldElement51 {
        let mut output = *self;
        let mut temp = *self;
        fiat_25519_carry_square(&mut temp.0, &self.0);
        fiat_25519_add(&mut output.0, &temp.0, &temp.0);
        let input = output.0;
        fiat_25519_carry(&mut output.0, &input);
        output
    }
}
