use crate::FieldBytes;
use elliptic_curve::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::Zeroize,
};

#[derive(Clone, Copy, Debug)]
pub struct FieldElement10x26(pub(crate) [u32; 10]);

impl FieldElement10x26 {
    pub const fn zero() -> Self {
        Self([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    pub const fn one() -> Self {
        Self([1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        let w0 = (bytes[31] as u32)
            | ((bytes[30] as u32) << 8)
            | ((bytes[29] as u32) << 16)
            | (((bytes[28] & 0x3) as u32) << 24);
        let w1 = (((bytes[28] >> 2) as u32) & 0x3f)
            | ((bytes[27] as u32) << 6)
            | ((bytes[26] as u32) << 14)
            | (((bytes[25] & 0xf) as u32) << 22);
        let w2 = (((bytes[25] >> 4) as u32) & 0xf)
            | ((bytes[24] as u32) << 4)
            | ((bytes[23] as u32) << 12)
            | (((bytes[22] & 0x3f) as u32) << 20);
        let w3 = (((bytes[22] >> 6) as u32) & 0x3)
            | ((bytes[21] as u32) << 2)
            | ((bytes[20] as u32) << 10)
            | ((bytes[19] as u32) << 18);
        let w4 = (bytes[18] as u32)
            | ((bytes[17] as u32) << 8)
            | ((bytes[16] as u32) << 16)
            | (((bytes[15] & 0x3) as u32) << 24);
        let w5 = (((bytes[15] >> 2) as u32) & 0x3f)
            | ((bytes[14] as u32) << 6)
            | ((bytes[13] as u32) << 14)
            | (((bytes[12] & 0xf) as u32) << 22);
        let w6 = (((bytes[12] >> 4) as u32) & 0xf)
            | ((bytes[11] as u32) << 4)
            | ((bytes[10] as u32) << 12)
            | (((bytes[9] & 0x3f) as u32) << 20);
        let w7 = (((bytes[9] >> 6) as u32) & 0x3)
            | ((bytes[8] as u32) << 2)
            | ((bytes[7] as u32) << 10)
            | ((bytes[6] as u32) << 18);
        let w8 = (bytes[5] as u32)
            | ((bytes[4] as u32) << 8)
            | ((bytes[3] as u32) << 16)
            | (((bytes[2] & 0x3) as u32) << 24);
        let w9 = (((bytes[2] >> 2) as u32) & 0x3f)
            | ((bytes[1] as u32) << 6)
            | ((bytes[0] as u32) << 14);

        Self([w0, w1, w2, w3, w4, w5, w6, w7, w8, w9])
    }

    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
        let res = Self::from_bytes_unchecked(bytes.as_ref());
        let overflow = res.get_overflow();

        CtOption::new(res, !overflow)
    }

    pub fn to_bytes(self) -> FieldBytes {
        let mut r = FieldBytes::default();
        r[0] = (self.0[9] >> 14) as u8;
        r[1] = (self.0[9] >> 6) as u8;
        r[2] = ((self.0[9] as u8 & 0x3Fu8) << 2) | ((self.0[8] >> 24) as u8 & 0x3);
        r[3] = (self.0[8] >> 16) as u8;
        r[4] = (self.0[8] >> 8) as u8;
        r[5] = self.0[8] as u8;
        r[6] = (self.0[7] >> 18) as u8;
        r[7] = (self.0[7] >> 10) as u8;
        r[8] = (self.0[7] >> 2) as u8;
        r[9] = ((self.0[7] as u8 & 0x3u8) << 6) | ((self.0[6] >> 20) as u8 & 0x3fu8);
        r[10] = (self.0[6] >> 12) as u8;
        r[11] = (self.0[6] >> 4) as u8;
        r[12] = ((self.0[6] as u8 & 0xfu8) << 4) | ((self.0[5] >> 22) as u8 & 0xfu8);
        r[13] = (self.0[5] >> 14) as u8;
        r[14] = (self.0[5] >> 6) as u8;
        r[15] = ((self.0[5] as u8 & 0x3fu8) << 2) | ((self.0[4] >> 24) as u8 & 0x3u8);
        r[16] = (self.0[4] >> 16) as u8;
        r[17] = (self.0[4] >> 8) as u8;
        r[18] = self.0[4] as u8;
        r[19] = (self.0[3] >> 18) as u8;
        r[20] = (self.0[3] >> 10) as u8;
        r[21] = (self.0[3] >> 2) as u8;
        r[22] = ((self.0[3] as u8 & 0x3u8) << 6) | ((self.0[2] >> 20) as u8 & 0x3fu8);
        r[23] = (self.0[2] >> 12) as u8;
        r[24] = (self.0[2] >> 4) as u8;
        r[25] = ((self.0[2] as u8 & 0xfu8) << 4) | ((self.0[1] >> 22) as u8 & 0xfu8);
        r[26] = (self.0[1] >> 14) as u8;
        r[27] = (self.0[1] >> 6) as u8;
        r[28] = ((self.0[1] as u8 & 0x3fu8) << 2) | ((self.0[0] >> 24) as u8 & 0x3u8);
        r[29] = (self.0[0] >> 16) as u8;
        r[30] = (self.0[0] >> 8) as u8;
        r[31] = self.0[0] as u8;
        r
    }

    fn add_modulus_correction(&self, x: u32) -> Self {
        let t0 = self.0[0] + x * 0x3D1u32;

        let t1 = self.0[1] + (x << 6);
        let t1 = t1 + (t0 >> 26);
        let t0 = t0 & 0x3FFFFFFu32;

        let t2 = self.0[2] + (t1 >> 26);
        let t1 = t1 & 0x3FFFFFFu32;

        let t3 = self.0[3] + (t2 >> 26);
        let t2 = t2 & 0x3FFFFFFu32;

        let t4 = self.0[4] + (t3 >> 26);
        let t3 = t3 & 0x3FFFFFFu32;

        let t5 = self.0[5] + (t4 >> 26);
        let t4 = t4 & 0x3FFFFFFu32;

        let t6 = self.0[6] + (t5 >> 26);
        let t5 = t5 & 0x3FFFFFFu32;

        let t7 = self.0[7] + (t6 >> 26);
        let t6 = t6 & 0x3FFFFFFu32;

        let t8 = self.0[8] + (t7 >> 26);
        let t7 = t7 & 0x3FFFFFFu32;

        let t9 = self.0[9] + (t8 >> 26);
        let t8 = t8 & 0x3FFFFFFu32;

        Self([t0, t1, t2, t3, t4, t5, t6, t7, t8, t9])
    }

    fn subtract_modulus_approximation(&self) -> (Self, u32) {
        let x = self.0[9] >> 22;
        let t9 = self.0[9] & 0x03FFFFFu32;
        (
            Self([
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6],
                self.0[7], self.0[8], t9,
            ]),
            x,
        )
    }

    fn get_overflow(&self) -> Choice {
        let m = self.0[2] & self.0[3] & self.0[4] & self.0[5] & self.0[6] & self.0[7] & self.0[8];
        let x = (self.0[9] >> 22 != 0)
            | ((self.0[9] == 0x3FFFFFu32)
                & (m == 0x3FFFFFFu32)
                & ((self.0[1] + 0x40u32 + ((self.0[0] + 0x3D1u32) >> 26)) > 0x3FFFFFFu32));
        Choice::from(x as u8)
    }

    pub fn normalize_weak(&self) -> Self {
        let (t, x) = self.subtract_modulus_approximation();

        let res = t.add_modulus_correction(x);

        debug_assert!(res.0[9] >> 23 == 0);

        res
    }

    pub fn normalize(&self) -> Self {
        let res = self.normalize_weak();

        let overflow = res.get_overflow();

        let res_corrected = res.add_modulus_correction(1u32);
        let (res_corrected, x) = res_corrected.subtract_modulus_approximation();

        debug_assert!(x == (overflow.unwrap_u8() as u32));

        Self::conditional_select(&res, &res_corrected, overflow)
    }

    pub fn normalizes_to_zero(&self) -> Choice {
        let res = self.normalize_weak();

        let t0 = res.0[0];
        let t1 = res.0[1];
        let t2 = res.0[2];
        let t3 = res.0[3];
        let t4 = res.0[4];
        let t5 = res.0[5];
        let t6 = res.0[6];
        let t7 = res.0[7];
        let t8 = res.0[8];
        let t9 = res.0[9];

        let z0 = t0 | t1 | t2 | t3 | t4 | t5 | t6 | t7 | t8 | t9;
        let z1 = (t0 ^ 0x3D0u32)
            & (t1 ^ 0x40u32)
            & t2
            & t3
            & t4
            & t5
            & t6
            & t7
            & t8
            & (t9 ^ 0x3C00000u32);

        Choice::from(((z0 == 0) | (z1 == 0x3FFFFFFu32)) as u8)
    }

    pub fn is_zero(&self) -> Choice {
        Choice::from(
            ((self.0[0]
                | self.0[1]
                | self.0[2]
                | self.0[3]
                | self.0[4]
                | self.0[5]
                | self.0[6]
                | self.0[7]
                | self.0[8]
                | self.0[9])
                == 0) as u8,
        )
    }

    pub fn is_odd(&self) -> Choice {
        (self.0[0] as u8 & 1).into()
    }

    #[cfg(debug_assertions)]
    pub const fn max_magnitude() -> u32 {
        31u32
    }

    pub const fn negate(&self, magnitude: u32) -> Self {
        let m: u32 = magnitude + 1;
        let r0 = 0x3FFFC2Fu32 * 2 * m - self.0[0];
        let r1 = 0x3FFFFBFu32 * 2 * m - self.0[1];
        let r2 = 0x3FFFFFFu32 * 2 * m - self.0[2];
        let r3 = 0x3FFFFFFu32 * 2 * m - self.0[3];
        let r4 = 0x3FFFFFFu32 * 2 * m - self.0[4];
        let r5 = 0x3FFFFFFu32 * 2 * m - self.0[5];
        let r6 = 0x3FFFFFFu32 * 2 * m - self.0[6];
        let r7 = 0x3FFFFFFu32 * 2 * m - self.0[7];
        let r8 = 0x3FFFFFFu32 * 2 * m - self.0[8];
        let r9 = 0x03FFFFFu32 * 2 * m - self.0[9];
        Self([r0, r1, r2, r3, r4, r5, r6, r7, r8, r9])
    }

    pub const fn add(&self, rhs: &Self) -> Self {
        Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
            self.0[5] + rhs.0[5],
            self.0[6] + rhs.0[6],
            self.0[7] + rhs.0[7],
            self.0[8] + rhs.0[8],
            self.0[9] + rhs.0[9],
        ])
    }

    pub const fn mul_single(&self, rhs: u32) -> Self {
        Self([
            self.0[0] * rhs,
            self.0[1] * rhs,
            self.0[2] * rhs,
            self.0[3] * rhs,
            self.0[4] * rhs,
            self.0[5] * rhs,
            self.0[6] * rhs,
            self.0[7] * rhs,
            self.0[8] * rhs,
            self.0[9] * rhs,
        ])
    }

    #[inline(always)]
    fn mul_inner(&self, rhs: &Self) -> Self {
        let m = 0x3FFFFFFu64;
        let rr0 = 0x3D10u64;
        let rr1 = 0x400u64;

        let a0 = self.0[0] as u64;
        let a1 = self.0[1] as u64;
        let a2 = self.0[2] as u64;
        let a3 = self.0[3] as u64;
        let a4 = self.0[4] as u64;
        let a5 = self.0[5] as u64;
        let a6 = self.0[6] as u64;
        let a7 = self.0[7] as u64;
        let a8 = self.0[8] as u64;
        let a9 = self.0[9] as u64;

        let b0 = rhs.0[0] as u64;
        let b1 = rhs.0[1] as u64;
        let b2 = rhs.0[2] as u64;
        let b3 = rhs.0[3] as u64;
        let b4 = rhs.0[4] as u64;
        let b5 = rhs.0[5] as u64;
        let b6 = rhs.0[6] as u64;
        let b7 = rhs.0[7] as u64;
        let b8 = rhs.0[8] as u64;
        let b9 = rhs.0[9] as u64;

        let mut c: u64;
        let mut d: u64;

        d = a0 * b9
            + a1 * b8
            + a2 * b7
            + a3 * b6
            + a4 * b5
            + a5 * b4
            + a6 * b3
            + a7 * b2
            + a8 * b1
            + a9 * b0;
        let t9 = (d & m) as u32;
        d >>= 26;
        debug_assert!(t9 >> 26 == 0);
        debug_assert!(d >> 38 == 0);

        c = a0 * b0;
        debug_assert!(c >> 60 == 0);
        d +=
            a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1;
        debug_assert!(d >> 63 == 0);
        let u0 = (d & m) as u32;
        d >>= 26;
        c += u0 as u64 * rr0;
        debug_assert!(u0 >> 26 == 0);
        debug_assert!(d >> 37 == 0);
        debug_assert!(c >> 61 == 0);
        let t0 = (c & m) as u32;
        c >>= 26;
        c += u0 as u64 * rr1;
        debug_assert!(t0 >> 26 == 0);
        debug_assert!(c >> 37 == 0);

        c += a0 * b1 + a1 * b0;
        debug_assert!(c >> 62 == 0);
        d += a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2;
        debug_assert!(d >> 63 == 0);
        let u1 = (d & m) as u32;
        d >>= 26;
        c += u1 as u64 * rr0;
        debug_assert!(u1 >> 26 == 0);
        debug_assert!(d >> 37 == 0);
        debug_assert!(c >> 63 == 0);
        let t1 = (c & m) as u32;
        c >>= 26;
        c += u1 as u64 * rr1;
        debug_assert!(t1 >> 26 == 0);
        debug_assert!(c >> 38 == 0);

        c += a0 * b2 + a1 * b1 + a2 * b0;
        debug_assert!(c >> 62 == 0);
        d += a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3;
        debug_assert!(d >> 63 == 0);
        let u2 = (d & m) as u32;
        d >>= 26;
        c += u2 as u64 * rr0;
        debug_assert!(u2 >> 26 == 0);
        debug_assert!(d >> 37 == 0);
        debug_assert!(c >> 63 == 0);
        let t2 = (c & m) as u32;
        c >>= 26;
        c += u2 as u64 * rr1;
        debug_assert!(t2 >> 26 == 0);
        debug_assert!(c >> 38 == 0);

        c += a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
        debug_assert!(c >> 63 == 0);
        d += a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4;
        debug_assert!(d >> 63 == 0);
        let u3 = (d & m) as u32;
        d >>= 26;
        c += u3 as u64 * rr0;
        debug_assert!(u3 >> 26 == 0);
        debug_assert!(d >> 37 == 0);
        let t3 = (c & m) as u32;
        c >>= 26;
        c += u3 as u64 * rr1;
        debug_assert!(t3 >> 26 == 0);
        debug_assert!(c >> 39 == 0);

        c += a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
        debug_assert!(c >> 63 == 0);
        d += a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5;
        debug_assert!(d >> 62 == 0);
        let u4 = (d & m) as u32;
        d >>= 26;
        c += u4 as u64 * rr0;
        debug_assert!(u4 >> 26 == 0);
        debug_assert!(d >> 36 == 0);
        let t4 = (c & m) as u32;
        c >>= 26;
        c += u4 as u64 * rr1;
        debug_assert!(t4 >> 26 == 0);
        debug_assert!(c >> 39 == 0);

        c += a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
        debug_assert!(c >> 63 == 0);
        d += a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6;
        debug_assert!(d >> 62 == 0);
        let u5 = (d & m) as u32;
        d >>= 26;
        c += u5 as u64 * rr0;
        debug_assert!(u5 >> 26 == 0);
        debug_assert!(d >> 36 == 0);
        let t5 = (c & m) as u32;
        c >>= 26;
        c += u5 as u64 * rr1;
        debug_assert!(t5 >> 26 == 0);
        debug_assert!(c >> 39 == 0);

        c += a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
        debug_assert!(c >> 63 == 0);
        d += a7 * b9 + a8 * b8 + a9 * b7;
        debug_assert!(d >> 61 == 0);
        let u6 = (d & m) as u32;
        d >>= 26;
        c += u6 as u64 * rr0;
        debug_assert!(u6 >> 26 == 0);
        debug_assert!(d >> 35 == 0);
        let t6 = (c & m) as u32;
        c >>= 26;
        c += u6 as u64 * rr1;
        debug_assert!(t6 >> 26 == 0);
        debug_assert!(c >> 39 == 0);

        c += a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
        debug_assert!(c <= 0x8000007C00000007u64);
        d += a8 * b9 + a9 * b8;
        debug_assert!(d >> 58 == 0);
        let u7 = (d & m) as u32;
        d >>= 26;
        c += u7 as u64 * rr0;
        debug_assert!(u7 >> 26 == 0);
        debug_assert!(d >> 32 == 0);
        let d32 = d as u32;
        debug_assert!(c <= 0x800001703FFFC2F7u64);
        let t7 = (c & m) as u32;
        c >>= 26;
        c += u7 as u64 * rr1;
        debug_assert!(t7 >> 26 == 0);
        debug_assert!(c >> 38 == 0);

        c +=
            a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
        debug_assert!(c <= 0x9000007B80000008u64);
        d = d32 as u64 + a9 * b9;
        debug_assert!(d >> 57 == 0);
        let u8 = (d & m) as u32;
        d >>= 26;
        c += u8 as u64 * rr0;
        debug_assert!(u8 >> 26 == 0);
        debug_assert!(d >> 31 == 0);
        let d32 = d as u32;
        debug_assert!(c <= 0x9000016FBFFFC2F8u64);

        let r3 = t3;
        debug_assert!(r3 >> 26 == 0);
        let r4 = t4;
        debug_assert!(r4 >> 26 == 0);
        let r5 = t5;
        debug_assert!(r5 >> 26 == 0);
        let r6 = t6;
        debug_assert!(r6 >> 26 == 0);
        let r7 = t7;
        debug_assert!(r7 >> 26 == 0);

        let r8 = (c & m) as u32;
        c >>= 26;
        c += u8 as u64 * rr1;
        debug_assert!(r8 >> 26 == 0);
        debug_assert!(c >> 39 == 0);
        c += d32 as u64 * rr0 + t9 as u64;
        debug_assert!(c >> 45 == 0);
        let r9 = (c & (m >> 4)) as u32;
        c >>= 22;
        c += d * (rr1 << 4);
        debug_assert!(r9 >> 22 == 0);
        debug_assert!(c >> 46 == 0);

        d = c * (rr0 >> 4) + t0 as u64;
        debug_assert!(d >> 56 == 0);
        let r0 = (d & m) as u32;
        d >>= 26;
        debug_assert!(r0 >> 26 == 0);
        debug_assert!(d >> 30 == 0);
        let d32 = d as u32;
        d = d32 as u64 + c * (rr1 >> 4) + t1 as u64;
        debug_assert!(d >> 53 == 0);
        debug_assert!(d <= 0x10000003FFFFBFu64);
        let r1 = (d & m) as u32;
        d >>= 26;
        debug_assert!(r1 >> 26 == 0);
        debug_assert!(d >> 27 == 0);
        let d32 = d as u32;
        debug_assert!(d <= 0x4000000u64);
        d = d32 as u64 + t2 as u64;
        debug_assert!(d >> 27 == 0);
        let r2 = d as u32;
        debug_assert!(r2 >> 27 == 0);

        Self([r0, r1, r2, r3, r4, r5, r6, r7, r8, r9])
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        self.mul_inner(rhs)
    }

    pub fn square(&self) -> Self {
        self.mul_inner(self)
    }
}

impl Default for FieldElement10x26 {
    fn default() -> Self {
        Self::zero()
    }
}

impl ConditionallySelectable for FieldElement10x26 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self([
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
}

impl ConstantTimeEq for FieldElement10x26 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
            & self.0[4].ct_eq(&other.0[4])
            & self.0[5].ct_eq(&other.0[5])
            & self.0[6].ct_eq(&other.0[6])
            & self.0[7].ct_eq(&other.0[7])
            & self.0[8].ct_eq(&other.0[8])
            & self.0[9].ct_eq(&other.0[9])
    }
}

impl Zeroize for FieldElement10x26 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement10x26;

    #[test]
    fn overflow_check_after_weak_normalize() {
        let z = FieldElement10x26([
            (1 << 26),
            (1 << 26) - 1,
            (1 << 26) - 1,
            (1 << 26) - 1,
            (1 << 26) - 1,
            (1 << 26) - 1,
            (1 << 26) - 1,
            (1 << 26) - 1,
            (1 << 26) - 1,
            (1 << 22) - 1,
        ]);

        let z_normalized = z.normalize();

        let z_reference = FieldElement10x26([0x3d1, 0x40, 0, 0, 0, 0, 0, 0, 0, 0]);

        assert_eq!(z_normalized.0, z_reference.0);
    }
}
