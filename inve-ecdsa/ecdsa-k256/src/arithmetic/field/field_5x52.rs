use crate::FieldBytes;
use elliptic_curve::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::Zeroize,
};

#[derive(Clone, Copy, Debug)]
pub struct FieldElement5x52(pub(crate) [u64; 5]);

impl FieldElement5x52 {
    pub const fn zero() -> Self {
        Self([0, 0, 0, 0, 0])
    }

    pub const fn one() -> Self {
        Self([1, 0, 0, 0, 0])
    }

    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        let w0 = (bytes[31] as u64)
            | ((bytes[30] as u64) << 8)
            | ((bytes[29] as u64) << 16)
            | ((bytes[28] as u64) << 24)
            | ((bytes[27] as u64) << 32)
            | ((bytes[26] as u64) << 40)
            | (((bytes[25] & 0xFu8) as u64) << 48);

        let w1 = ((bytes[25] >> 4) as u64)
            | ((bytes[24] as u64) << 4)
            | ((bytes[23] as u64) << 12)
            | ((bytes[22] as u64) << 20)
            | ((bytes[21] as u64) << 28)
            | ((bytes[20] as u64) << 36)
            | ((bytes[19] as u64) << 44);

        let w2 = (bytes[18] as u64)
            | ((bytes[17] as u64) << 8)
            | ((bytes[16] as u64) << 16)
            | ((bytes[15] as u64) << 24)
            | ((bytes[14] as u64) << 32)
            | ((bytes[13] as u64) << 40)
            | (((bytes[12] & 0xFu8) as u64) << 48);

        let w3 = ((bytes[12] >> 4) as u64)
            | ((bytes[11] as u64) << 4)
            | ((bytes[10] as u64) << 12)
            | ((bytes[9] as u64) << 20)
            | ((bytes[8] as u64) << 28)
            | ((bytes[7] as u64) << 36)
            | ((bytes[6] as u64) << 44);

        let w4 = (bytes[5] as u64)
            | ((bytes[4] as u64) << 8)
            | ((bytes[3] as u64) << 16)
            | ((bytes[2] as u64) << 24)
            | ((bytes[1] as u64) << 32)
            | ((bytes[0] as u64) << 40);

        Self([w0, w1, w2, w3, w4])
    }

    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
        let res = Self::from_bytes_unchecked(bytes.as_ref());
        let overflow = res.get_overflow();
        CtOption::new(res, !overflow)
    }

    pub fn to_bytes(self) -> FieldBytes {
        let mut ret = FieldBytes::default();
        ret[0] = (self.0[4] >> 40) as u8;
        ret[1] = (self.0[4] >> 32) as u8;
        ret[2] = (self.0[4] >> 24) as u8;
        ret[3] = (self.0[4] >> 16) as u8;
        ret[4] = (self.0[4] >> 8) as u8;
        ret[5] = self.0[4] as u8;
        ret[6] = (self.0[3] >> 44) as u8;
        ret[7] = (self.0[3] >> 36) as u8;
        ret[8] = (self.0[3] >> 28) as u8;
        ret[9] = (self.0[3] >> 20) as u8;
        ret[10] = (self.0[3] >> 12) as u8;
        ret[11] = (self.0[3] >> 4) as u8;
        ret[12] = ((self.0[2] >> 48) as u8 & 0xFu8) | ((self.0[3] as u8 & 0xFu8) << 4);
        ret[13] = (self.0[2] >> 40) as u8;
        ret[14] = (self.0[2] >> 32) as u8;
        ret[15] = (self.0[2] >> 24) as u8;
        ret[16] = (self.0[2] >> 16) as u8;
        ret[17] = (self.0[2] >> 8) as u8;
        ret[18] = self.0[2] as u8;
        ret[19] = (self.0[1] >> 44) as u8;
        ret[20] = (self.0[1] >> 36) as u8;
        ret[21] = (self.0[1] >> 28) as u8;
        ret[22] = (self.0[1] >> 20) as u8;
        ret[23] = (self.0[1] >> 12) as u8;
        ret[24] = (self.0[1] >> 4) as u8;
        ret[25] = ((self.0[0] >> 48) as u8 & 0xFu8) | ((self.0[1] as u8 & 0xFu8) << 4);
        ret[26] = (self.0[0] >> 40) as u8;
        ret[27] = (self.0[0] >> 32) as u8;
        ret[28] = (self.0[0] >> 24) as u8;
        ret[29] = (self.0[0] >> 16) as u8;
        ret[30] = (self.0[0] >> 8) as u8;
        ret[31] = self.0[0] as u8;
        ret
    }

    fn add_modulus_correction(&self, x: u64) -> Self {
        let t0 = self.0[0] + x * 0x1000003D1u64;

        let t1 = self.0[1] + (t0 >> 52);
        let t0 = t0 & 0xFFFFFFFFFFFFFu64;

        let t2 = self.0[2] + (t1 >> 52);
        let t1 = t1 & 0xFFFFFFFFFFFFFu64;

        let t3 = self.0[3] + (t2 >> 52);
        let t2 = t2 & 0xFFFFFFFFFFFFFu64;

        let t4 = self.0[4] + (t3 >> 52);
        let t3 = t3 & 0xFFFFFFFFFFFFFu64;

        Self([t0, t1, t2, t3, t4])
    }

    fn subtract_modulus_approximation(&self) -> (Self, u64) {
        let x = self.0[4] >> 48;
        let t4 = self.0[4] & 0x0FFFFFFFFFFFFu64;
        (Self([self.0[0], self.0[1], self.0[2], self.0[3], t4]), x)
    }

    fn get_overflow(&self) -> Choice {
        let m = self.0[1] & self.0[2] & self.0[3];
        let x = (self.0[4] >> 48 != 0)
            | ((self.0[4] == 0x0FFFFFFFFFFFFu64)
                & (m == 0xFFFFFFFFFFFFFu64)
                & (self.0[0] >= 0xFFFFEFFFFFC2Fu64));
        Choice::from(x as u8)
    }

    pub fn normalize_weak(&self) -> Self {
        let (t, x) = self.subtract_modulus_approximation();

        let res = t.add_modulus_correction(x);

        debug_assert!(res.0[4] >> 49 == 0);

        res
    }

    pub fn normalize(&self) -> Self {
        let res = self.normalize_weak();

        let overflow = res.get_overflow();

        let res_corrected = res.add_modulus_correction(1u64);
        let (res_corrected, x) = res_corrected.subtract_modulus_approximation();

        debug_assert!(x == (overflow.unwrap_u8() as u64));

        Self::conditional_select(&res, &res_corrected, overflow)
    }

    pub fn normalizes_to_zero(&self) -> Choice {
        let res = self.normalize_weak();

        let t0 = res.0[0];
        let t1 = res.0[1];
        let t2 = res.0[2];
        let t3 = res.0[3];
        let t4 = res.0[4];

        let z0 = t0 | t1 | t2 | t3 | t4;
        let z1 = (t0 ^ 0x1000003D0u64) & t1 & t2 & t3 & (t4 ^ 0xF000000000000u64);

        Choice::from(((z0 == 0) | (z1 == 0xFFFFFFFFFFFFFu64)) as u8)
    }

    pub fn is_zero(&self) -> Choice {
        Choice::from(((self.0[0] | self.0[1] | self.0[2] | self.0[3] | self.0[4]) == 0) as u8)
    }

    pub fn is_odd(&self) -> Choice {
        (self.0[0] as u8 & 1).into()
    }

    #[cfg(debug_assertions)]
    pub const fn max_magnitude() -> u32 {
        2047u32
    }

    pub const fn negate(&self, magnitude: u32) -> Self {
        let m = (magnitude + 1) as u64;
        let r0 = 0xFFFFEFFFFFC2Fu64 * 2 * m - self.0[0];
        let r1 = 0xFFFFFFFFFFFFFu64 * 2 * m - self.0[1];
        let r2 = 0xFFFFFFFFFFFFFu64 * 2 * m - self.0[2];
        let r3 = 0xFFFFFFFFFFFFFu64 * 2 * m - self.0[3];
        let r4 = 0x0FFFFFFFFFFFFu64 * 2 * m - self.0[4];
        Self([r0, r1, r2, r3, r4])
    }

    pub const fn add(&self, rhs: &Self) -> Self {
        Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }

    pub const fn mul_single(&self, rhs: u32) -> Self {
        let rhs_u64 = rhs as u64;
        Self([
            self.0[0] * rhs_u64,
            self.0[1] * rhs_u64,
            self.0[2] * rhs_u64,
            self.0[3] * rhs_u64,
            self.0[4] * rhs_u64,
        ])
    }

    #[inline(always)]
    fn mul_inner(&self, rhs: &Self) -> Self {
        let a0 = self.0[0] as u128;
        let a1 = self.0[1] as u128;
        let a2 = self.0[2] as u128;
        let a3 = self.0[3] as u128;
        let a4 = self.0[4] as u128;
        let b0 = rhs.0[0] as u128;
        let b1 = rhs.0[1] as u128;
        let b2 = rhs.0[2] as u128;
        let b3 = rhs.0[3] as u128;
        let b4 = rhs.0[4] as u128;
        let m = 0xFFFFFFFFFFFFFu128;
        let r = 0x1000003D10u128;

        debug_assert!(a0 >> 56 == 0);
        debug_assert!(a1 >> 56 == 0);
        debug_assert!(a2 >> 56 == 0);
        debug_assert!(a3 >> 56 == 0);
        debug_assert!(a4 >> 52 == 0);

        debug_assert!(b0 >> 56 == 0);
        debug_assert!(b1 >> 56 == 0);
        debug_assert!(b2 >> 56 == 0);
        debug_assert!(b3 >> 56 == 0);
        debug_assert!(b4 >> 52 == 0);

        let mut c: u128;
        let mut d: u128;

        d = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
        debug_assert!(d >> 114 == 0);
        c = a4 * b4;
        debug_assert!(c >> 112 == 0);
        d += (c & m) * r;
        c >>= 52;
        debug_assert!(d >> 115 == 0);
        debug_assert!(c >> 60 == 0);
        let c64 = c as u64;
        let t3 = (d & m) as u64;
        d >>= 52;
        debug_assert!(t3 >> 52 == 0);
        debug_assert!(d >> 63 == 0);
        let d64 = d as u64;

        d = d64 as u128 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
        debug_assert!(d >> 115 == 0);
        d += c64 as u128 * r;
        debug_assert!(d >> 116 == 0);
        let t4 = (d & m) as u64;
        d >>= 52;
        debug_assert!(t4 >> 52 == 0);
        debug_assert!(d >> 64 == 0);
        let d64 = d as u64;
        let tx = t4 >> 48;
        let t4 = t4 & ((m as u64) >> 4);
        debug_assert!(tx >> 4 == 0);
        debug_assert!(t4 >> 48 == 0);

        c = a0 * b0;
        debug_assert!(c >> 112 == 0);
        d = d64 as u128 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1;
        debug_assert!(d >> 115 == 0);
        let u0 = (d & m) as u64;
        d >>= 52;
        debug_assert!(u0 >> 52 == 0);
        debug_assert!(d >> 63 == 0);
        let d64 = d as u64;
        let u0 = (u0 << 4) | tx;
        debug_assert!(u0 >> 56 == 0);
        c += u0 as u128 * ((r as u64) >> 4) as u128;
        debug_assert!(c >> 115 == 0);
        let r0 = (c & m) as u64;
        c >>= 52;
        debug_assert!(r0 >> 52 == 0);
        debug_assert!(c >> 61 == 0);
        let c64 = c as u64;

        c = c64 as u128 + a0 * b1 + a1 * b0;
        debug_assert!(c >> 114 == 0);
        d = d64 as u128 + a2 * b4 + a3 * b3 + a4 * b2;
        debug_assert!(d >> 114 == 0);
        c += (d & m) * r;
        d >>= 52;
        debug_assert!(c >> 115 == 0);
        debug_assert!(d >> 62 == 0);
        let d64 = d as u64;
        let r1 = (c & m) as u64;
        c >>= 52;
        debug_assert!(r1 >> 52 == 0);
        debug_assert!(c >> 63 == 0);
        let c64 = c as u64;

        c = c64 as u128 + a0 * b2 + a1 * b1 + a2 * b0;
        debug_assert!(c >> 114 == 0);
        d = d64 as u128 + a3 * b4 + a4 * b3;
        debug_assert!(d >> 114 == 0);
        c += (d & m) * r;
        d >>= 52;
        debug_assert!(c >> 115 == 0);
        debug_assert!(d >> 62 == 0);
        let d64 = d as u64;

        let r2 = (c & m) as u64;
        c >>= 52;
        debug_assert!(r2 >> 52 == 0);
        debug_assert!(c >> 63 == 0);
        let c64 = c as u64;
        c = c64 as u128 + (d64 as u128) * r + t3 as u128;
        debug_assert!(c >> 100 == 0);
        let r3 = (c & m) as u64;
        c >>= 52;
        debug_assert!(r3 >> 52 == 0);
        debug_assert!(c >> 48 == 0);
        let c64 = c as u64;
        c = c64 as u128 + t4 as u128;
        debug_assert!(c >> 49 == 0);
        let r4 = c as u64;
        debug_assert!(r4 >> 49 == 0);

        Self([r0, r1, r2, r3, r4])
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        self.mul_inner(rhs)
    }

    pub fn square(&self) -> Self {
        self.mul_inner(self)
    }
}

impl Default for FieldElement5x52 {
    fn default() -> Self {
        Self::zero()
    }
}

impl ConditionallySelectable for FieldElement5x52 {
    fn conditional_select(
        a: &FieldElement5x52,
        b: &FieldElement5x52,
        choice: Choice,
    ) -> FieldElement5x52 {
        FieldElement5x52([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
            u64::conditional_select(&a.0[4], &b.0[4], choice),
        ])
    }
}

impl ConstantTimeEq for FieldElement5x52 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
            & self.0[4].ct_eq(&other.0[4])
    }
}

impl Zeroize for FieldElement5x52 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement5x52;

    #[test]
    fn overflow_check_after_weak_normalize() {
        let z = FieldElement5x52([
            (1 << 52),
            (1 << 52) - 1,
            (1 << 52) - 1,
            (1 << 52) - 1,
            (1 << 48) - 1,
        ]);

        let z_normalized = z.normalize();

        let z_reference = FieldElement5x52([0x1000003d1, 0, 0, 0, 0]);

        assert_eq!(z_normalized.0, z_reference.0);
    }
}
