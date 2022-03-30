use core::fmt::Debug;
use core::ops::Neg;
use core::ops::{Add, AddAssign};
use core::ops::{Mul, MulAssign};
use core::ops::{Sub, SubAssign};

use subtle::Choice;
use subtle::ConditionallySelectable;

use zeroize::Zeroize;

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
        for i in 0..10 {
            self.0[i] += _rhs.0[i];
        }
    }
}

impl<'a, 'b> Add<&'b FieldElement2625> for &'a FieldElement2625 {
    type Output = FieldElement2625;
    fn add(self, _rhs: &'b FieldElement2625) -> FieldElement2625 {
        let mut output = *self;
        output += _rhs;
        output
    }
}

impl<'b> SubAssign<&'b FieldElement2625> for FieldElement2625 {
    fn sub_assign(&mut self, _rhs: &'b FieldElement2625) {
        let b = &_rhs.0;
        self.0 = FieldElement2625::reduce([
            ((self.0[0] + (0x3ffffed << 4)) - b[0]) as u64,
            ((self.0[1] + (0x1ffffff << 4)) - b[1]) as u64,
            ((self.0[2] + (0x3ffffff << 4)) - b[2]) as u64,
            ((self.0[3] + (0x1ffffff << 4)) - b[3]) as u64,
            ((self.0[4] + (0x3ffffff << 4)) - b[4]) as u64,
            ((self.0[5] + (0x1ffffff << 4)) - b[5]) as u64,
            ((self.0[6] + (0x3ffffff << 4)) - b[6]) as u64,
            ((self.0[7] + (0x1ffffff << 4)) - b[7]) as u64,
            ((self.0[8] + (0x3ffffff << 4)) - b[8]) as u64,
            ((self.0[9] + (0x1ffffff << 4)) - b[9]) as u64,
        ])
        .0;
    }
}

impl<'a, 'b> Sub<&'b FieldElement2625> for &'a FieldElement2625 {
    type Output = FieldElement2625;
    fn sub(self, _rhs: &'b FieldElement2625) -> FieldElement2625 {
        let mut output = *self;
        output -= _rhs;
        output
    }
}

impl<'b> MulAssign<&'b FieldElement2625> for FieldElement2625 {
    fn mul_assign(&mut self, _rhs: &'b FieldElement2625) {
        let result = (self as &FieldElement2625) * _rhs;
        self.0 = result.0;
    }
}

impl<'a, 'b> Mul<&'b FieldElement2625> for &'a FieldElement2625 {
    type Output = FieldElement2625;
    fn mul(self, _rhs: &'b FieldElement2625) -> FieldElement2625 {
        #[inline(always)]
        fn m(x: u32, y: u32) -> u64 {
            (x as u64) * (y as u64)
        }

        let x: &[u32; 10] = &self.0;
        let y: &[u32; 10] = &_rhs.0;

        let y1_19 = 19 * y[1];
        let y2_19 = 19 * y[2];
        let y3_19 = 19 * y[3];
        let y4_19 = 19 * y[4];
        let y5_19 = 19 * y[5];
        let y6_19 = 19 * y[6];
        let y7_19 = 19 * y[7];
        let y8_19 = 19 * y[8];
        let y9_19 = 19 * y[9];

        let x1_2 = 2 * x[1];
        let x3_2 = 2 * x[3];
        let x5_2 = 2 * x[5];
        let x7_2 = 2 * x[7];
        let x9_2 = 2 * x[9];

        let z0 = m(x[0], y[0])
            + m(x1_2, y9_19)
            + m(x[2], y8_19)
            + m(x3_2, y7_19)
            + m(x[4], y6_19)
            + m(x5_2, y5_19)
            + m(x[6], y4_19)
            + m(x7_2, y3_19)
            + m(x[8], y2_19)
            + m(x9_2, y1_19);
        let z1 = m(x[0], y[1])
            + m(x[1], y[0])
            + m(x[2], y9_19)
            + m(x[3], y8_19)
            + m(x[4], y7_19)
            + m(x[5], y6_19)
            + m(x[6], y5_19)
            + m(x[7], y4_19)
            + m(x[8], y3_19)
            + m(x[9], y2_19);
        let z2 = m(x[0], y[2])
            + m(x1_2, y[1])
            + m(x[2], y[0])
            + m(x3_2, y9_19)
            + m(x[4], y8_19)
            + m(x5_2, y7_19)
            + m(x[6], y6_19)
            + m(x7_2, y5_19)
            + m(x[8], y4_19)
            + m(x9_2, y3_19);
        let z3 = m(x[0], y[3])
            + m(x[1], y[2])
            + m(x[2], y[1])
            + m(x[3], y[0])
            + m(x[4], y9_19)
            + m(x[5], y8_19)
            + m(x[6], y7_19)
            + m(x[7], y6_19)
            + m(x[8], y5_19)
            + m(x[9], y4_19);
        let z4 = m(x[0], y[4])
            + m(x1_2, y[3])
            + m(x[2], y[2])
            + m(x3_2, y[1])
            + m(x[4], y[0])
            + m(x5_2, y9_19)
            + m(x[6], y8_19)
            + m(x7_2, y7_19)
            + m(x[8], y6_19)
            + m(x9_2, y5_19);
        let z5 = m(x[0], y[5])
            + m(x[1], y[4])
            + m(x[2], y[3])
            + m(x[3], y[2])
            + m(x[4], y[1])
            + m(x[5], y[0])
            + m(x[6], y9_19)
            + m(x[7], y8_19)
            + m(x[8], y7_19)
            + m(x[9], y6_19);
        let z6 = m(x[0], y[6])
            + m(x1_2, y[5])
            + m(x[2], y[4])
            + m(x3_2, y[3])
            + m(x[4], y[2])
            + m(x5_2, y[1])
            + m(x[6], y[0])
            + m(x7_2, y9_19)
            + m(x[8], y8_19)
            + m(x9_2, y7_19);
        let z7 = m(x[0], y[7])
            + m(x[1], y[6])
            + m(x[2], y[5])
            + m(x[3], y[4])
            + m(x[4], y[3])
            + m(x[5], y[2])
            + m(x[6], y[1])
            + m(x[7], y[0])
            + m(x[8], y9_19)
            + m(x[9], y8_19);
        let z8 = m(x[0], y[8])
            + m(x1_2, y[7])
            + m(x[2], y[6])
            + m(x3_2, y[5])
            + m(x[4], y[4])
            + m(x5_2, y[3])
            + m(x[6], y[2])
            + m(x7_2, y[1])
            + m(x[8], y[0])
            + m(x9_2, y9_19);
        let z9 = m(x[0], y[9])
            + m(x[1], y[8])
            + m(x[2], y[7])
            + m(x[3], y[6])
            + m(x[4], y[5])
            + m(x[5], y[4])
            + m(x[6], y[3])
            + m(x[7], y[2])
            + m(x[8], y[1])
            + m(x[9], y[0]);

        FieldElement2625::reduce([z0, z1, z2, z3, z4, z5, z6, z7, z8, z9])
    }
}

impl<'a> Neg for &'a FieldElement2625 {
    type Output = FieldElement2625;
    fn neg(self) -> FieldElement2625 {
        let mut output = *self;
        output.negate();
        output
    }
}

impl ConditionallySelectable for FieldElement2625 {
    fn conditional_select(
        a: &FieldElement2625,
        b: &FieldElement2625,
        choice: Choice,
    ) -> FieldElement2625 {
        FieldElement2625([
            u32::conditional_select(&a.0[0], &b.0[0], choice),
            u32::conditional_select(&a.0[1], &b.0[1], choice),
            u32::conditional_select(&a.0[2], &b.0[2], choice),
            u32::conditional_select(&a.0[3], &b.0[3], choice),
            u32::conditional_select(&a.0[4], &b.0[4], choice),
            u32::conditional_select(&a.0[5], &b.0[5], choice),
            u32::conditional_select(&a.0[6], &b.0[6], choice),
            u32::conditional_select(&a.0[7], &b.0[7], choice),
            u32::conditional_select(&a.0[8], &b.0[8], choice),
            u32::conditional_select(&a.0[9], &b.0[9], choice),
        ])
    }

    fn conditional_assign(&mut self, other: &FieldElement2625, choice: Choice) {
        self.0[0].conditional_assign(&other.0[0], choice);
        self.0[1].conditional_assign(&other.0[1], choice);
        self.0[2].conditional_assign(&other.0[2], choice);
        self.0[3].conditional_assign(&other.0[3], choice);
        self.0[4].conditional_assign(&other.0[4], choice);
        self.0[5].conditional_assign(&other.0[5], choice);
        self.0[6].conditional_assign(&other.0[6], choice);
        self.0[7].conditional_assign(&other.0[7], choice);
        self.0[8].conditional_assign(&other.0[8], choice);
        self.0[9].conditional_assign(&other.0[9], choice);
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
        let neg = FieldElement2625::reduce([
            ((0x3ffffed << 4) - self.0[0]) as u64,
            ((0x1ffffff << 4) - self.0[1]) as u64,
            ((0x3ffffff << 4) - self.0[2]) as u64,
            ((0x1ffffff << 4) - self.0[3]) as u64,
            ((0x3ffffff << 4) - self.0[4]) as u64,
            ((0x1ffffff << 4) - self.0[5]) as u64,
            ((0x3ffffff << 4) - self.0[6]) as u64,
            ((0x1ffffff << 4) - self.0[7]) as u64,
            ((0x3ffffff << 4) - self.0[8]) as u64,
            ((0x1ffffff << 4) - self.0[9]) as u64,
        ]);
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

    fn reduce(mut z: [u64; 10]) -> FieldElement2625 {
        const LOW_25_BITS: u64 = (1 << 25) - 1;
        const LOW_26_BITS: u64 = (1 << 26) - 1;

        #[inline(always)]
        fn carry(z: &mut [u64; 10], i: usize) {
            debug_assert!(i < 9);
            if i % 2 == 0 {
                z[i + 1] += z[i] >> 26;
                z[i] &= LOW_26_BITS;
            } else {
                z[i + 1] += z[i] >> 25;
                z[i] &= LOW_25_BITS;
            }
        }

        carry(&mut z, 0);
        carry(&mut z, 4);
        carry(&mut z, 1);
        carry(&mut z, 5);
        carry(&mut z, 2);
        carry(&mut z, 6);
        carry(&mut z, 3);
        carry(&mut z, 7);
        carry(&mut z, 4);
        carry(&mut z, 8);

        z[0] += 19 * (z[9] >> 25);
        z[9] &= LOW_25_BITS;

        carry(&mut z, 0);

        FieldElement2625([
            z[0] as u32,
            z[1] as u32,
            z[2] as u32,
            z[3] as u32,
            z[4] as u32,
            z[5] as u32,
            z[6] as u32,
            z[7] as u32,
            z[8] as u32,
            z[9] as u32,
        ])
    }

    pub fn from_bytes(data: &[u8; 32]) -> FieldElement2625 {
        #[inline]
        fn load3(b: &[u8]) -> u64 {
            (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16)
        }

        #[inline]
        fn load4(b: &[u8]) -> u64 {
            (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16) | ((b[3] as u64) << 24)
        }

        let mut h = [0u64; 10];
        const LOW_23_BITS: u64 = (1 << 23) - 1;
        h[0] = load4(&data[0..]);
        h[1] = load3(&data[4..]) << 6;
        h[2] = load3(&data[7..]) << 5;
        h[3] = load3(&data[10..]) << 3;
        h[4] = load3(&data[13..]) << 2;
        h[5] = load4(&data[16..]);
        h[6] = load3(&data[20..]) << 7;
        h[7] = load3(&data[23..]) << 5;
        h[8] = load3(&data[26..]) << 4;
        h[9] = (load3(&data[29..]) & LOW_23_BITS) << 2;

        FieldElement2625::reduce(h)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let inp = &self.0;
        let mut h: [u32; 10] = FieldElement2625::reduce([
            inp[0] as u64,
            inp[1] as u64,
            inp[2] as u64,
            inp[3] as u64,
            inp[4] as u64,
            inp[5] as u64,
            inp[6] as u64,
            inp[7] as u64,
            inp[8] as u64,
            inp[9] as u64,
        ])
        .0;

        let mut q: u32 = (h[0] + 19) >> 26;
        q = (h[1] + q) >> 25;
        q = (h[2] + q) >> 26;
        q = (h[3] + q) >> 25;
        q = (h[4] + q) >> 26;
        q = (h[5] + q) >> 25;
        q = (h[6] + q) >> 26;
        q = (h[7] + q) >> 25;
        q = (h[8] + q) >> 26;
        q = (h[9] + q) >> 25;

        debug_assert!(q == 0 || q == 1);

        const LOW_25_BITS: u32 = (1 << 25) - 1;
        const LOW_26_BITS: u32 = (1 << 26) - 1;

        h[0] += 19 * q;

        h[1] += h[0] >> 26;
        h[0] = h[0] & LOW_26_BITS;
        h[2] += h[1] >> 25;
        h[1] = h[1] & LOW_25_BITS;
        h[3] += h[2] >> 26;
        h[2] = h[2] & LOW_26_BITS;
        h[4] += h[3] >> 25;
        h[3] = h[3] & LOW_25_BITS;
        h[5] += h[4] >> 26;
        h[4] = h[4] & LOW_26_BITS;
        h[6] += h[5] >> 25;
        h[5] = h[5] & LOW_25_BITS;
        h[7] += h[6] >> 26;
        h[6] = h[6] & LOW_26_BITS;
        h[8] += h[7] >> 25;
        h[7] = h[7] & LOW_25_BITS;
        h[9] += h[8] >> 26;
        h[8] = h[8] & LOW_26_BITS;

        debug_assert!((h[9] >> 25) == 0 || (h[9] >> 25) == 1);
        h[9] = h[9] & LOW_25_BITS;

        let mut s = [0u8; 32];
        s[0] = (h[0] >> 0) as u8;
        s[1] = (h[0] >> 8) as u8;
        s[2] = (h[0] >> 16) as u8;
        s[3] = ((h[0] >> 24) | (h[1] << 2)) as u8;
        s[4] = (h[1] >> 6) as u8;
        s[5] = (h[1] >> 14) as u8;
        s[6] = ((h[1] >> 22) | (h[2] << 3)) as u8;
        s[7] = (h[2] >> 5) as u8;
        s[8] = (h[2] >> 13) as u8;
        s[9] = ((h[2] >> 21) | (h[3] << 5)) as u8;
        s[10] = (h[3] >> 3) as u8;
        s[11] = (h[3] >> 11) as u8;
        s[12] = ((h[3] >> 19) | (h[4] << 6)) as u8;
        s[13] = (h[4] >> 2) as u8;
        s[14] = (h[4] >> 10) as u8;
        s[15] = (h[4] >> 18) as u8;
        s[16] = (h[5] >> 0) as u8;
        s[17] = (h[5] >> 8) as u8;
        s[18] = (h[5] >> 16) as u8;
        s[19] = ((h[5] >> 24) | (h[6] << 1)) as u8;
        s[20] = (h[6] >> 7) as u8;
        s[21] = (h[6] >> 15) as u8;
        s[22] = ((h[6] >> 23) | (h[7] << 3)) as u8;
        s[23] = (h[7] >> 5) as u8;
        s[24] = (h[7] >> 13) as u8;
        s[25] = ((h[7] >> 21) | (h[8] << 4)) as u8;
        s[26] = (h[8] >> 4) as u8;
        s[27] = (h[8] >> 12) as u8;
        s[28] = ((h[8] >> 20) | (h[9] << 6)) as u8;
        s[29] = (h[9] >> 2) as u8;
        s[30] = (h[9] >> 10) as u8;
        s[31] = (h[9] >> 18) as u8;

        debug_assert!((s[31] & 0b1000_0000u8) == 0u8);

        s
    }

    fn square_inner(&self) -> [u64; 10] {
        let x = &self.0;
        let x0_2 = 2 * x[0];
        let x1_2 = 2 * x[1];
        let x2_2 = 2 * x[2];
        let x3_2 = 2 * x[3];
        let x4_2 = 2 * x[4];
        let x5_2 = 2 * x[5];
        let x6_2 = 2 * x[6];
        let x7_2 = 2 * x[7];
        let x5_19 = 19 * x[5];
        let x6_19 = 19 * x[6];
        let x7_19 = 19 * x[7];
        let x8_19 = 19 * x[8];
        let x9_19 = 19 * x[9];

        #[inline(always)]
        fn m(x: u32, y: u32) -> u64 {
            (x as u64) * (y as u64)
        }

        let mut z = [0u64; 10];
        z[0] = m(x[0], x[0])
            + m(x2_2, x8_19)
            + m(x4_2, x6_19)
            + (m(x1_2, x9_19) + m(x3_2, x7_19) + m(x[5], x5_19)) * 2;
        z[1] =
            m(x0_2, x[1]) + m(x3_2, x8_19) + m(x5_2, x6_19) + (m(x[2], x9_19) + m(x[4], x7_19)) * 2;
        z[2] = m(x0_2, x[2])
            + m(x1_2, x[1])
            + m(x4_2, x8_19)
            + m(x[6], x6_19)
            + (m(x3_2, x9_19) + m(x5_2, x7_19)) * 2;
        z[3] =
            m(x0_2, x[3]) + m(x1_2, x[2]) + m(x5_2, x8_19) + (m(x[4], x9_19) + m(x[6], x7_19)) * 2;
        z[4] = m(x0_2, x[4])
            + m(x1_2, x3_2)
            + m(x[2], x[2])
            + m(x6_2, x8_19)
            + (m(x5_2, x9_19) + m(x[7], x7_19)) * 2;
        z[5] = m(x0_2, x[5]) + m(x1_2, x[4]) + m(x2_2, x[3]) + m(x7_2, x8_19) + m(x[6], x9_19) * 2;
        z[6] = m(x0_2, x[6])
            + m(x1_2, x5_2)
            + m(x2_2, x[4])
            + m(x3_2, x[3])
            + m(x[8], x8_19)
            + m(x7_2, x9_19) * 2;
        z[7] = m(x0_2, x[7]) + m(x1_2, x[6]) + m(x2_2, x[5]) + m(x3_2, x[4]) + m(x[8], x9_19) * 2;
        z[8] = m(x0_2, x[8])
            + m(x1_2, x7_2)
            + m(x2_2, x[6])
            + m(x3_2, x5_2)
            + m(x[4], x[4])
            + m(x[9], x9_19) * 2;
        z[9] = m(x0_2, x[9]) + m(x1_2, x[8]) + m(x2_2, x[7]) + m(x3_2, x[6]) + m(x4_2, x[5]);

        z
    }

    pub fn square(&self) -> FieldElement2625 {
        FieldElement2625::reduce(self.square_inner())
    }

    pub fn square2(&self) -> FieldElement2625 {
        let mut coeffs = self.square_inner();
        for i in 0..self.0.len() {
            coeffs[i] += coeffs[i];
        }
        FieldElement2625::reduce(coeffs)
    }
}
