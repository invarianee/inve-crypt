use core::fmt::Debug;
use core::ops::Neg;
use core::ops::{Add, AddAssign};
use core::ops::{Mul, MulAssign};
use core::ops::{Sub, SubAssign};

use subtle::Choice;
use subtle::ConditionallySelectable;

use zeroize::Zeroize;

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
        for i in 0..5 {
            self.0[i] += _rhs.0[i];
        }
    }
}

impl<'a, 'b> Add<&'b FieldElement51> for &'a FieldElement51 {
    type Output = FieldElement51;
    fn add(self, _rhs: &'b FieldElement51) -> FieldElement51 {
        let mut output = *self;
        output += _rhs;
        output
    }
}

impl<'b> SubAssign<&'b FieldElement51> for FieldElement51 {
    fn sub_assign(&mut self, _rhs: &'b FieldElement51) {
        let result = (self as &FieldElement51) - _rhs;
        self.0 = result.0;
    }
}

impl<'a, 'b> Sub<&'b FieldElement51> for &'a FieldElement51 {
    type Output = FieldElement51;
    fn sub(self, _rhs: &'b FieldElement51) -> FieldElement51 {
        FieldElement51::reduce([
            (self.0[0] + 36028797018963664u64) - _rhs.0[0],
            (self.0[1] + 36028797018963952u64) - _rhs.0[1],
            (self.0[2] + 36028797018963952u64) - _rhs.0[2],
            (self.0[3] + 36028797018963952u64) - _rhs.0[3],
            (self.0[4] + 36028797018963952u64) - _rhs.0[4],
        ])
    }
}

impl<'b> MulAssign<&'b FieldElement51> for FieldElement51 {
    fn mul_assign(&mut self, _rhs: &'b FieldElement51) {
        let result = (self as &FieldElement51) * _rhs;
        self.0 = result.0;
    }
}

impl<'a, 'b> Mul<&'b FieldElement51> for &'a FieldElement51 {
    type Output = FieldElement51;
    fn mul(self, _rhs: &'b FieldElement51) -> FieldElement51 {
        #[inline(always)]
        fn m(x: u64, y: u64) -> u128 {
            (x as u128) * (y as u128)
        }

        let a: &[u64; 5] = &self.0;
        let b: &[u64; 5] = &_rhs.0;

        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;

        let c0: u128 =
            m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
        let mut c1: u128 =
            m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
        let mut c2: u128 =
            m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19);
        let mut c3: u128 =
            m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19);
        let mut c4: u128 =
            m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);

        debug_assert!(a[0] < (1 << 54));
        debug_assert!(b[0] < (1 << 54));
        debug_assert!(a[1] < (1 << 54));
        debug_assert!(b[1] < (1 << 54));
        debug_assert!(a[2] < (1 << 54));
        debug_assert!(b[2] < (1 << 54));
        debug_assert!(a[3] < (1 << 54));
        debug_assert!(b[3] < (1 << 54));
        debug_assert!(a[4] < (1 << 54));
        debug_assert!(b[4] < (1 << 54));

        const LOW_51_BIT_MASK: u64 = (1u64 << 51) - 1;
        let mut out = [0u64; 5];

        c1 += ((c0 >> 51) as u64) as u128;
        out[0] = (c0 as u64) & LOW_51_BIT_MASK;

        c2 += ((c1 >> 51) as u64) as u128;
        out[1] = (c1 as u64) & LOW_51_BIT_MASK;

        c3 += ((c2 >> 51) as u64) as u128;
        out[2] = (c2 as u64) & LOW_51_BIT_MASK;

        c4 += ((c3 >> 51) as u64) as u128;
        out[3] = (c3 as u64) & LOW_51_BIT_MASK;

        let carry: u64 = (c4 >> 51) as u64;
        out[4] = (c4 as u64) & LOW_51_BIT_MASK;

        out[0] = out[0] + carry * 19;

        out[1] += out[0] >> 51;
        out[0] &= LOW_51_BIT_MASK;

        FieldElement51(out)
    }
}

impl<'a> Neg for &'a FieldElement51 {
    type Output = FieldElement51;
    fn neg(self) -> FieldElement51 {
        let mut output = *self;
        output.negate();
        output
    }
}

impl ConditionallySelectable for FieldElement51 {
    fn conditional_select(
        a: &FieldElement51,
        b: &FieldElement51,
        choice: Choice,
    ) -> FieldElement51 {
        FieldElement51([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
            u64::conditional_select(&a.0[4], &b.0[4], choice),
        ])
    }

    fn conditional_swap(a: &mut FieldElement51, b: &mut FieldElement51, choice: Choice) {
        u64::conditional_swap(&mut a.0[0], &mut b.0[0], choice);
        u64::conditional_swap(&mut a.0[1], &mut b.0[1], choice);
        u64::conditional_swap(&mut a.0[2], &mut b.0[2], choice);
        u64::conditional_swap(&mut a.0[3], &mut b.0[3], choice);
        u64::conditional_swap(&mut a.0[4], &mut b.0[4], choice);
    }

    fn conditional_assign(&mut self, other: &FieldElement51, choice: Choice) {
        self.0[0].conditional_assign(&other.0[0], choice);
        self.0[1].conditional_assign(&other.0[1], choice);
        self.0[2].conditional_assign(&other.0[2], choice);
        self.0[3].conditional_assign(&other.0[3], choice);
        self.0[4].conditional_assign(&other.0[4], choice);
    }
}

impl FieldElement51 {
    pub fn negate(&mut self) {
        let neg = FieldElement51::reduce([
            36028797018963664u64 - self.0[0],
            36028797018963952u64 - self.0[1],
            36028797018963952u64 - self.0[2],
            36028797018963952u64 - self.0[3],
            36028797018963952u64 - self.0[4],
        ]);
        self.0 = neg.0;
    }

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
    fn reduce(mut limbs: [u64; 5]) -> FieldElement51 {
        const LOW_51_BIT_MASK: u64 = (1u64 << 51) - 1;

        let c0 = limbs[0] >> 51;
        let c1 = limbs[1] >> 51;
        let c2 = limbs[2] >> 51;
        let c3 = limbs[3] >> 51;
        let c4 = limbs[4] >> 51;

        limbs[0] &= LOW_51_BIT_MASK;
        limbs[1] &= LOW_51_BIT_MASK;
        limbs[2] &= LOW_51_BIT_MASK;
        limbs[3] &= LOW_51_BIT_MASK;
        limbs[4] &= LOW_51_BIT_MASK;

        limbs[0] += c4 * 19;
        limbs[1] += c0;
        limbs[2] += c1;
        limbs[3] += c2;
        limbs[4] += c3;

        FieldElement51(limbs)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> FieldElement51 {
        let load8 = |input: &[u8]| -> u64 {
            (input[0] as u64)
                | ((input[1] as u64) << 8)
                | ((input[2] as u64) << 16)
                | ((input[3] as u64) << 24)
                | ((input[4] as u64) << 32)
                | ((input[5] as u64) << 40)
                | ((input[6] as u64) << 48)
                | ((input[7] as u64) << 56)
        };

        let low_51_bit_mask = (1u64 << 51) - 1;
        FieldElement51([
            load8(&bytes[0..]) & low_51_bit_mask,
            (load8(&bytes[6..]) >> 3) & low_51_bit_mask,
            (load8(&bytes[12..]) >> 6) & low_51_bit_mask,
            (load8(&bytes[19..]) >> 1) & low_51_bit_mask,
            (load8(&bytes[24..]) >> 12) & low_51_bit_mask,
        ])
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut limbs = FieldElement51::reduce(self.0).0;

        let mut q = (limbs[0] + 19) >> 51;
        q = (limbs[1] + q) >> 51;
        q = (limbs[2] + q) >> 51;
        q = (limbs[3] + q) >> 51;
        q = (limbs[4] + q) >> 51;

        limbs[0] += 19 * q;

        let low_51_bit_mask = (1u64 << 51) - 1;
        limbs[1] += limbs[0] >> 51;
        limbs[0] = limbs[0] & low_51_bit_mask;
        limbs[2] += limbs[1] >> 51;
        limbs[1] = limbs[1] & low_51_bit_mask;
        limbs[3] += limbs[2] >> 51;
        limbs[2] = limbs[2] & low_51_bit_mask;
        limbs[4] += limbs[3] >> 51;
        limbs[3] = limbs[3] & low_51_bit_mask;
        limbs[4] = limbs[4] & low_51_bit_mask;

        let mut s = [0u8; 32];
        s[0] = limbs[0] as u8;
        s[1] = (limbs[0] >> 8) as u8;
        s[2] = (limbs[0] >> 16) as u8;
        s[3] = (limbs[0] >> 24) as u8;
        s[4] = (limbs[0] >> 32) as u8;
        s[5] = (limbs[0] >> 40) as u8;
        s[6] = ((limbs[0] >> 48) | (limbs[1] << 3)) as u8;
        s[7] = (limbs[1] >> 5) as u8;
        s[8] = (limbs[1] >> 13) as u8;
        s[9] = (limbs[1] >> 21) as u8;
        s[10] = (limbs[1] >> 29) as u8;
        s[11] = (limbs[1] >> 37) as u8;
        s[12] = ((limbs[1] >> 45) | (limbs[2] << 6)) as u8;
        s[13] = (limbs[2] >> 2) as u8;
        s[14] = (limbs[2] >> 10) as u8;
        s[15] = (limbs[2] >> 18) as u8;
        s[16] = (limbs[2] >> 26) as u8;
        s[17] = (limbs[2] >> 34) as u8;
        s[18] = (limbs[2] >> 42) as u8;
        s[19] = ((limbs[2] >> 50) | (limbs[3] << 1)) as u8;
        s[20] = (limbs[3] >> 7) as u8;
        s[21] = (limbs[3] >> 15) as u8;
        s[22] = (limbs[3] >> 23) as u8;
        s[23] = (limbs[3] >> 31) as u8;
        s[24] = (limbs[3] >> 39) as u8;
        s[25] = ((limbs[3] >> 47) | (limbs[4] << 4)) as u8;
        s[26] = (limbs[4] >> 4) as u8;
        s[27] = (limbs[4] >> 12) as u8;
        s[28] = (limbs[4] >> 20) as u8;
        s[29] = (limbs[4] >> 28) as u8;
        s[30] = (limbs[4] >> 36) as u8;
        s[31] = (limbs[4] >> 44) as u8;

        debug_assert!((s[31] & 0b1000_0000u8) == 0u8);

        s
    }

    pub fn pow2k(&self, mut k: u32) -> FieldElement51 {
        debug_assert!(k > 0);

        #[inline(always)]
        fn m(x: u64, y: u64) -> u128 {
            (x as u128) * (y as u128)
        }

        let mut a: [u64; 5] = self.0;

        loop {
            let a3_19 = 19 * a[3];
            let a4_19 = 19 * a[4];

            let c0: u128 = m(a[0], a[0]) + 2 * (m(a[1], a4_19) + m(a[2], a3_19));
            let mut c1: u128 = m(a[3], a3_19) + 2 * (m(a[0], a[1]) + m(a[2], a4_19));
            let mut c2: u128 = m(a[1], a[1]) + 2 * (m(a[0], a[2]) + m(a[4], a3_19));
            let mut c3: u128 = m(a[4], a4_19) + 2 * (m(a[0], a[3]) + m(a[1], a[2]));
            let mut c4: u128 = m(a[2], a[2]) + 2 * (m(a[0], a[4]) + m(a[1], a[3]));

            debug_assert!(a[0] < (1 << 54));
            debug_assert!(a[1] < (1 << 54));
            debug_assert!(a[2] < (1 << 54));
            debug_assert!(a[3] < (1 << 54));
            debug_assert!(a[4] < (1 << 54));

            const LOW_51_BIT_MASK: u64 = (1u64 << 51) - 1;

            c1 += ((c0 >> 51) as u64) as u128;
            a[0] = (c0 as u64) & LOW_51_BIT_MASK;

            c2 += ((c1 >> 51) as u64) as u128;
            a[1] = (c1 as u64) & LOW_51_BIT_MASK;

            c3 += ((c2 >> 51) as u64) as u128;
            a[2] = (c2 as u64) & LOW_51_BIT_MASK;

            c4 += ((c3 >> 51) as u64) as u128;
            a[3] = (c3 as u64) & LOW_51_BIT_MASK;

            let carry: u64 = (c4 >> 51) as u64;
            a[4] = (c4 as u64) & LOW_51_BIT_MASK;

            a[0] = a[0] + carry * 19;

            a[1] += a[0] >> 51;
            a[0] &= LOW_51_BIT_MASK;

            k = k - 1;
            if k == 0 {
                break;
            }
        }

        FieldElement51(a)
    }

    pub fn square(&self) -> FieldElement51 {
        self.pow2k(1)
    }

    pub fn square2(&self) -> FieldElement51 {
        let mut square = self.pow2k(1);
        for i in 0..5 {
            square.0[i] *= 2;
        }

        square
    }
}
