use core::fmt::Debug;
use core::ops::{Index, IndexMut};

use zeroize::Zeroize;

use constants;

#[derive(Copy, Clone)]
pub struct Scalar29(pub [u32; 9]);

impl Debug for Scalar29 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Scalar29: {:?}", &self.0[..])
    }
}

impl Zeroize for Scalar29 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Index<usize> for Scalar29 {
    type Output = u32;
    fn index(&self, _index: usize) -> &u32 {
        &(self.0[_index])
    }
}

impl IndexMut<usize> for Scalar29 {
    fn index_mut(&mut self, _index: usize) -> &mut u32 {
        &mut (self.0[_index])
    }
}

#[inline(always)]
fn m(x: u32, y: u32) -> u64 {
    (x as u64) * (y as u64)
}

impl Scalar29 {
    pub fn zero() -> Scalar29 {
        Scalar29([0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Scalar29 {
        let mut words = [0u32; 8];
        for i in 0..8 {
            for j in 0..4 {
                words[i] |= (bytes[(i * 4) + j] as u32) << (j * 8);
            }
        }

        let mask = (1u32 << 29) - 1;
        let top_mask = (1u32 << 24) - 1;
        let mut s = Scalar29::zero();

        s[0] = words[0] & mask;
        s[1] = ((words[0] >> 29) | (words[1] << 3)) & mask;
        s[2] = ((words[1] >> 26) | (words[2] << 6)) & mask;
        s[3] = ((words[2] >> 23) | (words[3] << 9)) & mask;
        s[4] = ((words[3] >> 20) | (words[4] << 12)) & mask;
        s[5] = ((words[4] >> 17) | (words[5] << 15)) & mask;
        s[6] = ((words[5] >> 14) | (words[6] << 18)) & mask;
        s[7] = ((words[6] >> 11) | (words[7] << 21)) & mask;
        s[8] = (words[7] >> 8) & top_mask;

        s
    }

    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar29 {
        let mut words = [0u32; 16];
        for i in 0..16 {
            for j in 0..4 {
                words[i] |= (bytes[(i * 4) + j] as u32) << (j * 8);
            }
        }

        let mask = (1u32 << 29) - 1;
        let mut lo = Scalar29::zero();
        let mut hi = Scalar29::zero();

        lo[0] = words[0] & mask;
        lo[1] = ((words[0] >> 29) | (words[1] << 3)) & mask;
        lo[2] = ((words[1] >> 26) | (words[2] << 6)) & mask;
        lo[3] = ((words[2] >> 23) | (words[3] << 9)) & mask;
        lo[4] = ((words[3] >> 20) | (words[4] << 12)) & mask;
        lo[5] = ((words[4] >> 17) | (words[5] << 15)) & mask;
        lo[6] = ((words[5] >> 14) | (words[6] << 18)) & mask;
        lo[7] = ((words[6] >> 11) | (words[7] << 21)) & mask;
        lo[8] = ((words[7] >> 8) | (words[8] << 24)) & mask;
        hi[0] = ((words[8] >> 5) | (words[9] << 27)) & mask;
        hi[1] = (words[9] >> 2) & mask;
        hi[2] = ((words[9] >> 31) | (words[10] << 1)) & mask;
        hi[3] = ((words[10] >> 28) | (words[11] << 4)) & mask;
        hi[4] = ((words[11] >> 25) | (words[12] << 7)) & mask;
        hi[5] = ((words[12] >> 22) | (words[13] << 10)) & mask;
        hi[6] = ((words[13] >> 19) | (words[14] << 13)) & mask;
        hi[7] = ((words[14] >> 16) | (words[15] << 16)) & mask;
        hi[8] = words[15] >> 13;

        lo = Scalar29::montgomery_mul(&lo, &constants::R);
        hi = Scalar29::montgomery_mul(&hi, &constants::RR);

        Scalar29::add(&hi, &lo)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut s = [0u8; 32];

        s[0] = (self.0[0] >> 0) as u8;
        s[1] = (self.0[0] >> 8) as u8;
        s[2] = (self.0[0] >> 16) as u8;
        s[3] = ((self.0[0] >> 24) | (self.0[1] << 5)) as u8;
        s[4] = (self.0[1] >> 3) as u8;
        s[5] = (self.0[1] >> 11) as u8;
        s[6] = (self.0[1] >> 19) as u8;
        s[7] = ((self.0[1] >> 27) | (self.0[2] << 2)) as u8;
        s[8] = (self.0[2] >> 6) as u8;
        s[9] = (self.0[2] >> 14) as u8;
        s[10] = ((self.0[2] >> 22) | (self.0[3] << 7)) as u8;
        s[11] = (self.0[3] >> 1) as u8;
        s[12] = (self.0[3] >> 9) as u8;
        s[13] = (self.0[3] >> 17) as u8;
        s[14] = ((self.0[3] >> 25) | (self.0[4] << 4)) as u8;
        s[15] = (self.0[4] >> 4) as u8;
        s[16] = (self.0[4] >> 12) as u8;
        s[17] = (self.0[4] >> 20) as u8;
        s[18] = ((self.0[4] >> 28) | (self.0[5] << 1)) as u8;
        s[19] = (self.0[5] >> 7) as u8;
        s[20] = (self.0[5] >> 15) as u8;
        s[21] = ((self.0[5] >> 23) | (self.0[6] << 6)) as u8;
        s[22] = (self.0[6] >> 2) as u8;
        s[23] = (self.0[6] >> 10) as u8;
        s[24] = (self.0[6] >> 18) as u8;
        s[25] = ((self.0[6] >> 26) | (self.0[7] << 3)) as u8;
        s[26] = (self.0[7] >> 5) as u8;
        s[27] = (self.0[7] >> 13) as u8;
        s[28] = (self.0[7] >> 21) as u8;
        s[29] = (self.0[8] >> 0) as u8;
        s[30] = (self.0[8] >> 8) as u8;
        s[31] = (self.0[8] >> 16) as u8;

        s
    }

    pub fn add(a: &Scalar29, b: &Scalar29) -> Scalar29 {
        let mut sum = Scalar29::zero();
        let mask = (1u32 << 29) - 1;

        let mut carry: u32 = 0;
        for i in 0..9 {
            carry = a[i] + b[i] + (carry >> 29);
            sum[i] = carry & mask;
        }

        Scalar29::sub(&sum, &constants::L)
    }

    pub fn sub(a: &Scalar29, b: &Scalar29) -> Scalar29 {
        let mut difference = Scalar29::zero();
        let mask = (1u32 << 29) - 1;

        let mut borrow: u32 = 0;
        for i in 0..9 {
            borrow = a[i].wrapping_sub(b[i] + (borrow >> 31));
            difference[i] = borrow & mask;
        }

        let underflow_mask = ((borrow >> 31) ^ 1).wrapping_sub(1);
        let mut carry: u32 = 0;
        for i in 0..9 {
            carry = (carry >> 29) + difference[i] + (constants::L[i] & underflow_mask);
            difference[i] = carry & mask;
        }

        difference
    }

    #[inline(always)]
    pub(crate) fn mul_internal(a: &Scalar29, b: &Scalar29) -> [u64; 17] {
        let mut z = [0u64; 17];

        z[0] = m(a[0], b[0]);
        z[1] = m(a[0], b[1]) + m(a[1], b[0]);
        z[2] = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]);
        z[3] = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]);
        z[4] = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        z[5] = m(a[1], b[4]) + m(a[2], b[3]) + m(a[3], b[2]) + m(a[4], b[1]);
        z[6] = m(a[2], b[4]) + m(a[3], b[3]) + m(a[4], b[2]);
        z[7] = m(a[3], b[4]) + m(a[4], b[3]);
        z[8] = (m(a[4], b[4])).wrapping_sub(z[3]);

        z[10] = z[5].wrapping_sub(m(a[5], b[5]));
        z[11] = z[6].wrapping_sub(m(a[5], b[6]) + m(a[6], b[5]));
        z[12] = z[7].wrapping_sub(m(a[5], b[7]) + m(a[6], b[6]) + m(a[7], b[5]));
        z[13] = m(a[5], b[8]) + m(a[6], b[7]) + m(a[7], b[6]) + m(a[8], b[5]);
        z[14] = m(a[6], b[8]) + m(a[7], b[7]) + m(a[8], b[6]);
        z[15] = m(a[7], b[8]) + m(a[8], b[7]);
        z[16] = m(a[8], b[8]);

        z[5] = z[10].wrapping_sub(z[0]);
        z[6] = z[11].wrapping_sub(z[1]);
        z[7] = z[12].wrapping_sub(z[2]);
        z[8] = z[8].wrapping_sub(z[13]);
        z[9] = z[14].wrapping_add(z[4]);
        z[10] = z[15].wrapping_add(z[10]);
        z[11] = z[16].wrapping_add(z[11]);

        let aa = [a[0] + a[5], a[1] + a[6], a[2] + a[7], a[3] + a[8]];

        let bb = [b[0] + b[5], b[1] + b[6], b[2] + b[7], b[3] + b[8]];

        z[5] = (m(aa[0], bb[0])).wrapping_add(z[5]);
        z[6] = (m(aa[0], bb[1]) + m(aa[1], bb[0])).wrapping_add(z[6]);
        z[7] = (m(aa[0], bb[2]) + m(aa[1], bb[1]) + m(aa[2], bb[0])).wrapping_add(z[7]);
        z[8] = (m(aa[0], bb[3]) + m(aa[1], bb[2]) + m(aa[2], bb[1]) + m(aa[3], bb[0]))
            .wrapping_add(z[8]);
        z[9] =
            (m(aa[0], b[4]) + m(aa[1], bb[3]) + m(aa[2], bb[2]) + m(aa[3], bb[1]) + m(a[4], bb[0]))
                .wrapping_sub(z[9]);
        z[10] = (m(aa[1], b[4]) + m(aa[2], bb[3]) + m(aa[3], bb[2]) + m(a[4], bb[1]))
            .wrapping_sub(z[10]);
        z[11] = (m(aa[2], b[4]) + m(aa[3], bb[3]) + m(a[4], bb[2])).wrapping_sub(z[11]);
        z[12] = (m(aa[3], b[4]) + m(a[4], bb[3])).wrapping_sub(z[12]);

        z
    }

    #[inline(always)]
    fn square_internal(a: &Scalar29) -> [u64; 17] {
        let aa = [
            a[0] * 2,
            a[1] * 2,
            a[2] * 2,
            a[3] * 2,
            a[4] * 2,
            a[5] * 2,
            a[6] * 2,
            a[7] * 2,
        ];

        [
            m(a[0], a[0]),
            m(aa[0], a[1]),
            m(aa[0], a[2]) + m(a[1], a[1]),
            m(aa[0], a[3]) + m(aa[1], a[2]),
            m(aa[0], a[4]) + m(aa[1], a[3]) + m(a[2], a[2]),
            m(aa[0], a[5]) + m(aa[1], a[4]) + m(aa[2], a[3]),
            m(aa[0], a[6]) + m(aa[1], a[5]) + m(aa[2], a[4]) + m(a[3], a[3]),
            m(aa[0], a[7]) + m(aa[1], a[6]) + m(aa[2], a[5]) + m(aa[3], a[4]),
            m(aa[0], a[8]) + m(aa[1], a[7]) + m(aa[2], a[6]) + m(aa[3], a[5]) + m(a[4], a[4]),
            m(aa[1], a[8]) + m(aa[2], a[7]) + m(aa[3], a[6]) + m(aa[4], a[5]),
            m(aa[2], a[8]) + m(aa[3], a[7]) + m(aa[4], a[6]) + m(a[5], a[5]),
            m(aa[3], a[8]) + m(aa[4], a[7]) + m(aa[5], a[6]),
            m(aa[4], a[8]) + m(aa[5], a[7]) + m(a[6], a[6]),
            m(aa[5], a[8]) + m(aa[6], a[7]),
            m(aa[6], a[8]) + m(a[7], a[7]),
            m(aa[7], a[8]),
            m(a[8], a[8]),
        ]
    }

    #[inline(always)]
    pub(crate) fn montgomery_reduce(limbs: &[u64; 17]) -> Scalar29 {
        #[inline(always)]
        fn part1(sum: u64) -> (u64, u32) {
            let p = (sum as u32).wrapping_mul(constants::LFACTOR) & ((1u32 << 29) - 1);
            ((sum + m(p, constants::L[0])) >> 29, p)
        }

        #[inline(always)]
        fn part2(sum: u64) -> (u64, u32) {
            let w = (sum as u32) & ((1u32 << 29) - 1);
            (sum >> 29, w)
        }

        let l = &constants::L;

        let (carry, n0) = part1(limbs[0]);
        let (carry, n1) = part1(carry + limbs[1] + m(n0, l[1]));
        let (carry, n2) = part1(carry + limbs[2] + m(n0, l[2]) + m(n1, l[1]));
        let (carry, n3) = part1(carry + limbs[3] + m(n0, l[3]) + m(n1, l[2]) + m(n2, l[1]));
        let (carry, n4) =
            part1(carry + limbs[4] + m(n0, l[4]) + m(n1, l[3]) + m(n2, l[2]) + m(n3, l[1]));
        let (carry, n5) =
            part1(carry + limbs[5] + m(n1, l[4]) + m(n2, l[3]) + m(n3, l[2]) + m(n4, l[1]));
        let (carry, n6) =
            part1(carry + limbs[6] + m(n2, l[4]) + m(n3, l[3]) + m(n4, l[2]) + m(n5, l[1]));
        let (carry, n7) =
            part1(carry + limbs[7] + m(n3, l[4]) + m(n4, l[3]) + m(n5, l[2]) + m(n6, l[1]));
        let (carry, n8) = part1(
            carry + limbs[8] + m(n0, l[8]) + m(n4, l[4]) + m(n5, l[3]) + m(n6, l[2]) + m(n7, l[1]),
        );

        let (carry, r0) = part2(
            carry + limbs[9] + m(n1, l[8]) + m(n5, l[4]) + m(n6, l[3]) + m(n7, l[2]) + m(n8, l[1]),
        );
        let (carry, r1) =
            part2(carry + limbs[10] + m(n2, l[8]) + m(n6, l[4]) + m(n7, l[3]) + m(n8, l[2]));
        let (carry, r2) = part2(carry + limbs[11] + m(n3, l[8]) + m(n7, l[4]) + m(n8, l[3]));
        let (carry, r3) = part2(carry + limbs[12] + m(n4, l[8]) + m(n8, l[4]));
        let (carry, r4) = part2(carry + limbs[13] + m(n5, l[8]));
        let (carry, r5) = part2(carry + limbs[14] + m(n6, l[8]));
        let (carry, r6) = part2(carry + limbs[15] + m(n7, l[8]));
        let (carry, r7) = part2(carry + limbs[16] + m(n8, l[8]));
        let r8 = carry as u32;

        Scalar29::sub(&Scalar29([r0, r1, r2, r3, r4, r5, r6, r7, r8]), l)
    }

    #[inline(never)]
    pub fn mul(a: &Scalar29, b: &Scalar29) -> Scalar29 {
        let ab = Scalar29::montgomery_reduce(&Scalar29::mul_internal(a, b));
        Scalar29::montgomery_reduce(&Scalar29::mul_internal(&ab, &constants::RR))
    }

    #[inline(never)]
    #[allow(dead_code)]
    pub fn square(&self) -> Scalar29 {
        let aa = Scalar29::montgomery_reduce(&Scalar29::square_internal(self));
        Scalar29::montgomery_reduce(&Scalar29::mul_internal(&aa, &constants::RR))
    }

    #[inline(never)]
    pub fn montgomery_mul(a: &Scalar29, b: &Scalar29) -> Scalar29 {
        Scalar29::montgomery_reduce(&Scalar29::mul_internal(a, b))
    }

    #[inline(never)]
    pub fn montgomery_square(&self) -> Scalar29 {
        Scalar29::montgomery_reduce(&Scalar29::square_internal(self))
    }

    #[inline(never)]
    pub fn to_montgomery(&self) -> Scalar29 {
        Scalar29::montgomery_mul(self, &constants::RR)
    }

    pub fn from_montgomery(&self) -> Scalar29 {
        let mut limbs = [0u64; 17];
        for i in 0..9 {
            limbs[i] = self[i] as u64;
        }
        Scalar29::montgomery_reduce(&limbs)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    pub static X: Scalar29 = Scalar29([
        0x1fffffff, 0x1fffffff, 0x1fffffff, 0x1fffffff, 0x1fffffff, 0x1fffffff, 0x1fffffff,
        0x1fffffff, 0x001fffff,
    ]);

    pub static XX: Scalar29 = Scalar29([
        0x00217559, 0x000b3401, 0x103ff43b, 0x1462a62c, 0x1d6f9f38, 0x18e7a42f, 0x09a3dcee,
        0x008dbe18, 0x0006ce65,
    ]);

    pub static XX_MONT: Scalar29 = Scalar29([
        0x152b4d2e, 0x0571d53b, 0x1da6d964, 0x188663b6, 0x1d1b5f92, 0x19d50e3f, 0x12306c29,
        0x0c6f26fe, 0x00030edb,
    ]);

    pub static Y: Scalar29 = Scalar29([
        0x1e1458fa, 0x165ba838, 0x1d787b36, 0x0e577f3a, 0x1d2baf06, 0x1d689a19, 0x1fff3047,
        0x117704ab, 0x000d9601,
    ]);

    pub static XY: Scalar29 = Scalar29([
        0x0ba7632d, 0x017736bb, 0x15c76138, 0x0c69daa1, 0x000001ba, 0x00000000, 0x00000000,
        0x00000000, 0x00000000,
    ]);

    pub static XY_MONT: Scalar29 = Scalar29([
        0x077b51e1, 0x1c64e119, 0x02a19ef5, 0x18d2129e, 0x00de0430, 0x045a7bc8, 0x04cfc7c9,
        0x1c002681, 0x000bdc1c,
    ]);

    pub static A: Scalar29 = Scalar29([
        0x07b3be89, 0x02291b60, 0x14a99f03, 0x07dc3787, 0x0a782aae, 0x16262525, 0x0cfdb93f,
        0x13f5718d, 0x000532da,
    ]);

    pub static B: Scalar29 = Scalar29([
        0x15421564, 0x1e69fd72, 0x093d9692, 0x161785be, 0x1587d69f, 0x09d9dada, 0x130246c0,
        0x0c0a8e72, 0x000acd25,
    ]);

    pub static AB: Scalar29 = Scalar29([
        0x0f677d12, 0x045236c0, 0x09533e06, 0x0fb86f0f, 0x14f0555c, 0x0c4c4a4a, 0x19fb727f,
        0x07eae31a, 0x000a65b5,
    ]);

    pub static C: Scalar29 = Scalar29([
        0x049c0f00, 0x00308f1a, 0x0164d1e9, 0x1c374ed1, 0x1be65d00, 0x19e90bfa, 0x08f73bb1,
        0x036f8613, 0x00039941,
    ]);

    #[test]
    fn mul_max() {
        let res = Scalar29::mul(&X, &X);
        for i in 0..9 {
            assert!(res[i] == XX[i]);
        }
    }

    #[test]
    fn square_max() {
        let res = X.square();
        for i in 0..9 {
            assert!(res[i] == XX[i]);
        }
    }

    #[test]
    fn montgomery_mul_max() {
        let res = Scalar29::montgomery_mul(&X, &X);
        for i in 0..9 {
            assert!(res[i] == XX_MONT[i]);
        }
    }

    #[test]
    fn montgomery_square_max() {
        let res = X.montgomery_square();
        for i in 0..9 {
            assert!(res[i] == XX_MONT[i]);
        }
    }

    #[test]
    fn mul() {
        let res = Scalar29::mul(&X, &Y);
        for i in 0..9 {
            assert!(res[i] == XY[i]);
        }
    }

    #[test]
    fn montgomery_mul() {
        let res = Scalar29::montgomery_mul(&X, &Y);
        for i in 0..9 {
            assert!(res[i] == XY_MONT[i]);
        }
    }

    #[test]
    fn add() {
        let res = Scalar29::add(&A, &B);
        let zero = Scalar29::zero();
        for i in 0..9 {
            assert!(res[i] == zero[i]);
        }
    }

    #[test]
    fn sub() {
        let res = Scalar29::sub(&A, &B);
        for i in 0..9 {
            assert!(res[i] == AB[i]);
        }
    }

    #[test]
    fn from_bytes_wide() {
        let bignum = [255u8; 64];
        let reduced = Scalar29::from_bytes_wide(&bignum);
        for i in 0..9 {
            assert!(reduced[i] == C[i]);
        }
    }
}
