use core::fmt::Debug;
use core::ops::{Index, IndexMut};

use zeroize::Zeroize;

use constants;

#[derive(Copy, Clone)]
pub struct Scalar52(pub [u64; 5]);

impl Debug for Scalar52 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Scalar52: {:?}", &self.0[..])
    }
}

impl Zeroize for Scalar52 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Index<usize> for Scalar52 {
    type Output = u64;
    fn index(&self, _index: usize) -> &u64 {
        &(self.0[_index])
    }
}

impl IndexMut<usize> for Scalar52 {
    fn index_mut(&mut self, _index: usize) -> &mut u64 {
        &mut (self.0[_index])
    }
}

#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}

impl Scalar52 {
    pub fn zero() -> Scalar52 {
        Scalar52([0, 0, 0, 0, 0])
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Scalar52 {
        let mut words = [0u64; 4];
        for i in 0..4 {
            for j in 0..8 {
                words[i] |= (bytes[(i * 8) + j] as u64) << (j * 8);
            }
        }

        let mask = (1u64 << 52) - 1;
        let top_mask = (1u64 << 48) - 1;
        let mut s = Scalar52::zero();

        s[0] = words[0] & mask;
        s[1] = ((words[0] >> 52) | (words[1] << 12)) & mask;
        s[2] = ((words[1] >> 40) | (words[2] << 24)) & mask;
        s[3] = ((words[2] >> 28) | (words[3] << 36)) & mask;
        s[4] = (words[3] >> 16) & top_mask;

        s
    }

    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar52 {
        let mut words = [0u64; 8];
        for i in 0..8 {
            for j in 0..8 {
                words[i] |= (bytes[(i * 8) + j] as u64) << (j * 8);
            }
        }

        let mask = (1u64 << 52) - 1;
        let mut lo = Scalar52::zero();
        let mut hi = Scalar52::zero();

        lo[0] = words[0] & mask;
        lo[1] = ((words[0] >> 52) | (words[1] << 12)) & mask;
        lo[2] = ((words[1] >> 40) | (words[2] << 24)) & mask;
        lo[3] = ((words[2] >> 28) | (words[3] << 36)) & mask;
        lo[4] = ((words[3] >> 16) | (words[4] << 48)) & mask;
        hi[0] = (words[4] >> 4) & mask;
        hi[1] = ((words[4] >> 56) | (words[5] << 8)) & mask;
        hi[2] = ((words[5] >> 44) | (words[6] << 20)) & mask;
        hi[3] = ((words[6] >> 32) | (words[7] << 32)) & mask;
        hi[4] = words[7] >> 20;

        lo = Scalar52::montgomery_mul(&lo, &constants::R);
        hi = Scalar52::montgomery_mul(&hi, &constants::RR);

        Scalar52::add(&hi, &lo)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut s = [0u8; 32];

        s[0] = (self.0[0] >> 0) as u8;
        s[1] = (self.0[0] >> 8) as u8;
        s[2] = (self.0[0] >> 16) as u8;
        s[3] = (self.0[0] >> 24) as u8;
        s[4] = (self.0[0] >> 32) as u8;
        s[5] = (self.0[0] >> 40) as u8;
        s[6] = ((self.0[0] >> 48) | (self.0[1] << 4)) as u8;
        s[7] = (self.0[1] >> 4) as u8;
        s[8] = (self.0[1] >> 12) as u8;
        s[9] = (self.0[1] >> 20) as u8;
        s[10] = (self.0[1] >> 28) as u8;
        s[11] = (self.0[1] >> 36) as u8;
        s[12] = (self.0[1] >> 44) as u8;
        s[13] = (self.0[2] >> 0) as u8;
        s[14] = (self.0[2] >> 8) as u8;
        s[15] = (self.0[2] >> 16) as u8;
        s[16] = (self.0[2] >> 24) as u8;
        s[17] = (self.0[2] >> 32) as u8;
        s[18] = (self.0[2] >> 40) as u8;
        s[19] = ((self.0[2] >> 48) | (self.0[3] << 4)) as u8;
        s[20] = (self.0[3] >> 4) as u8;
        s[21] = (self.0[3] >> 12) as u8;
        s[22] = (self.0[3] >> 20) as u8;
        s[23] = (self.0[3] >> 28) as u8;
        s[24] = (self.0[3] >> 36) as u8;
        s[25] = (self.0[3] >> 44) as u8;
        s[26] = (self.0[4] >> 0) as u8;
        s[27] = (self.0[4] >> 8) as u8;
        s[28] = (self.0[4] >> 16) as u8;
        s[29] = (self.0[4] >> 24) as u8;
        s[30] = (self.0[4] >> 32) as u8;
        s[31] = (self.0[4] >> 40) as u8;

        s
    }

    pub fn add(a: &Scalar52, b: &Scalar52) -> Scalar52 {
        let mut sum = Scalar52::zero();
        let mask = (1u64 << 52) - 1;

        let mut carry: u64 = 0;
        for i in 0..5 {
            carry = a[i] + b[i] + (carry >> 52);
            sum[i] = carry & mask;
        }

        Scalar52::sub(&sum, &constants::L)
    }

    pub fn sub(a: &Scalar52, b: &Scalar52) -> Scalar52 {
        let mut difference = Scalar52::zero();
        let mask = (1u64 << 52) - 1;

        let mut borrow: u64 = 0;
        for i in 0..5 {
            borrow = a[i].wrapping_sub(b[i] + (borrow >> 63));
            difference[i] = borrow & mask;
        }

        let underflow_mask = ((borrow >> 63) ^ 1).wrapping_sub(1);
        let mut carry: u64 = 0;
        for i in 0..5 {
            carry = (carry >> 52) + difference[i] + (constants::L[i] & underflow_mask);
            difference[i] = carry & mask;
        }

        difference
    }

    #[inline(always)]
    pub(crate) fn mul_internal(a: &Scalar52, b: &Scalar52) -> [u128; 9] {
        let mut z = [0u128; 9];

        z[0] = m(a[0], b[0]);
        z[1] = m(a[0], b[1]) + m(a[1], b[0]);
        z[2] = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]);
        z[3] = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]);
        z[4] = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        z[5] = m(a[1], b[4]) + m(a[2], b[3]) + m(a[3], b[2]) + m(a[4], b[1]);
        z[6] = m(a[2], b[4]) + m(a[3], b[3]) + m(a[4], b[2]);
        z[7] = m(a[3], b[4]) + m(a[4], b[3]);
        z[8] = m(a[4], b[4]);

        z
    }

    #[inline(always)]
    fn square_internal(a: &Scalar52) -> [u128; 9] {
        let aa = [a[0] * 2, a[1] * 2, a[2] * 2, a[3] * 2];

        [
            m(a[0], a[0]),
            m(aa[0], a[1]),
            m(aa[0], a[2]) + m(a[1], a[1]),
            m(aa[0], a[3]) + m(aa[1], a[2]),
            m(aa[0], a[4]) + m(aa[1], a[3]) + m(a[2], a[2]),
            m(aa[1], a[4]) + m(aa[2], a[3]),
            m(aa[2], a[4]) + m(a[3], a[3]),
            m(aa[3], a[4]),
            m(a[4], a[4]),
        ]
    }

    #[inline(always)]
    pub(crate) fn montgomery_reduce(limbs: &[u128; 9]) -> Scalar52 {
        #[inline(always)]
        fn part1(sum: u128) -> (u128, u64) {
            let p = (sum as u64).wrapping_mul(constants::LFACTOR) & ((1u64 << 52) - 1);
            ((sum + m(p, constants::L[0])) >> 52, p)
        }

        #[inline(always)]
        fn part2(sum: u128) -> (u128, u64) {
            let w = (sum as u64) & ((1u64 << 52) - 1);
            (sum >> 52, w)
        }

        let l = &constants::L;

        let (carry, n0) = part1(limbs[0]);
        let (carry, n1) = part1(carry + limbs[1] + m(n0, l[1]));
        let (carry, n2) = part1(carry + limbs[2] + m(n0, l[2]) + m(n1, l[1]));
        let (carry, n3) = part1(carry + limbs[3] + m(n1, l[2]) + m(n2, l[1]));
        let (carry, n4) = part1(carry + limbs[4] + m(n0, l[4]) + m(n2, l[2]) + m(n3, l[1]));

        let (carry, r0) = part2(carry + limbs[5] + m(n1, l[4]) + m(n3, l[2]) + m(n4, l[1]));
        let (carry, r1) = part2(carry + limbs[6] + m(n2, l[4]) + m(n4, l[2]));
        let (carry, r2) = part2(carry + limbs[7] + m(n3, l[4]));
        let (carry, r3) = part2(carry + limbs[8] + m(n4, l[4]));
        let r4 = carry as u64;

        Scalar52::sub(&Scalar52([r0, r1, r2, r3, r4]), l)
    }

    #[inline(never)]
    pub fn mul(a: &Scalar52, b: &Scalar52) -> Scalar52 {
        let ab = Scalar52::montgomery_reduce(&Scalar52::mul_internal(a, b));
        Scalar52::montgomery_reduce(&Scalar52::mul_internal(&ab, &constants::RR))
    }

    #[inline(never)]
    #[allow(dead_code)]
    pub fn square(&self) -> Scalar52 {
        let aa = Scalar52::montgomery_reduce(&Scalar52::square_internal(self));
        Scalar52::montgomery_reduce(&Scalar52::mul_internal(&aa, &constants::RR))
    }

    #[inline(never)]
    pub fn montgomery_mul(a: &Scalar52, b: &Scalar52) -> Scalar52 {
        Scalar52::montgomery_reduce(&Scalar52::mul_internal(a, b))
    }

    #[inline(never)]
    pub fn montgomery_square(&self) -> Scalar52 {
        Scalar52::montgomery_reduce(&Scalar52::square_internal(self))
    }

    #[inline(never)]
    pub fn to_montgomery(&self) -> Scalar52 {
        Scalar52::montgomery_mul(self, &constants::RR)
    }

    #[inline(never)]
    pub fn from_montgomery(&self) -> Scalar52 {
        let mut limbs = [0u128; 9];
        for i in 0..5 {
            limbs[i] = self[i] as u128;
        }
        Scalar52::montgomery_reduce(&limbs)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    pub static X: Scalar52 = Scalar52([
        0x000fffffffffffff,
        0x000fffffffffffff,
        0x000fffffffffffff,
        0x000fffffffffffff,
        0x00001fffffffffff,
    ]);

    pub static XX: Scalar52 = Scalar52([
        0x0001668020217559,
        0x000531640ffd0ec0,
        0x00085fd6f9f38a31,
        0x000c268f73bb1cf4,
        0x000006ce65046df0,
    ]);

    pub static XX_MONT: Scalar52 = Scalar52([
        0x000c754eea569a5c,
        0x00063b6ed36cb215,
        0x0008ffa36bf25886,
        0x000e9183614e7543,
        0x0000061db6c6f26f,
    ]);

    pub static Y: Scalar52 = Scalar52([
        0x000b75071e1458fa,
        0x000bf9d75e1ecdac,
        0x000433d2baf0672b,
        0x0005fffcc11fad13,
        0x00000d96018bb825,
    ]);

    pub static XY: Scalar52 = Scalar52([
        0x000ee6d76ba7632d,
        0x000ed50d71d84e02,
        0x00000000001ba634,
        0x0000000000000000,
        0x0000000000000000,
    ]);

    pub static XY_MONT: Scalar52 = Scalar52([
        0x0006d52bf200cfd5,
        0x00033fb1d7021570,
        0x000f201bc07139d8,
        0x0001267e3e49169e,
        0x000007b839c00268,
    ]);

    pub static A: Scalar52 = Scalar52([
        0x0005236c07b3be89,
        0x0001bc3d2a67c0c4,
        0x000a4aa782aae3ee,
        0x0006b3f6e4fec4c4,
        0x00000532da9fab8c,
    ]);

    pub static B: Scalar52 = Scalar52([
        0x000d3fae55421564,
        0x000c2df24f65a4bc,
        0x0005b5587d69fb0b,
        0x00094c091b013b3b,
        0x00000acd25605473,
    ]);

    pub static AB: Scalar52 = Scalar52([
        0x000a46d80f677d12,
        0x0003787a54cf8188,
        0x0004954f0555c7dc,
        0x000d67edc9fd8989,
        0x00000a65b53f5718,
    ]);

    pub static C: Scalar52 = Scalar52([
        0x000611e3449c0f00,
        0x000a768859347a40,
        0x0007f5be65d00e1b,
        0x0009a3dceec73d21,
        0x00000399411b7c30,
    ]);

    #[test]
    fn mul_max() {
        let res = Scalar52::mul(&X, &X);
        for i in 0..5 {
            assert!(res[i] == XX[i]);
        }
    }

    #[test]
    fn square_max() {
        let res = X.square();
        for i in 0..5 {
            assert!(res[i] == XX[i]);
        }
    }

    #[test]
    fn montgomery_mul_max() {
        let res = Scalar52::montgomery_mul(&X, &X);
        for i in 0..5 {
            assert!(res[i] == XX_MONT[i]);
        }
    }

    #[test]
    fn montgomery_square_max() {
        let res = X.montgomery_square();
        for i in 0..5 {
            assert!(res[i] == XX_MONT[i]);
        }
    }

    #[test]
    fn mul() {
        let res = Scalar52::mul(&X, &Y);
        for i in 0..5 {
            assert!(res[i] == XY[i]);
        }
    }

    #[test]
    fn montgomery_mul() {
        let res = Scalar52::montgomery_mul(&X, &Y);
        for i in 0..5 {
            assert!(res[i] == XY_MONT[i]);
        }
    }

    #[test]
    fn add() {
        let res = Scalar52::add(&A, &B);
        let zero = Scalar52::zero();
        for i in 0..5 {
            assert!(res[i] == zero[i]);
        }
    }

    #[test]
    fn sub() {
        let res = Scalar52::sub(&A, &B);
        for i in 0..5 {
            assert!(res[i] == AB[i]);
        }
    }

    #[test]
    fn from_bytes_wide() {
        let bignum = [255u8; 64];
        let reduced = Scalar52::from_bytes_wide(&bignum);
        for i in 0..5 {
            assert!(reduced[i] == C[i]);
        }
    }
}