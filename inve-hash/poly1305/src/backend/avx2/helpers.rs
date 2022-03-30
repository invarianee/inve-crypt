use core::fmt;
use core::ops::{Add, Mul};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::{Block, Key};

const fn set02(x3: u8, x2: u8, x1: u8, x0: u8) -> i32 {
    (((x3) << 6) | ((x2) << 4) | ((x1) << 2) | (x0)) as i32
}

fn write_130(f: &mut fmt::Formatter<'_>, limbs: [u32; 5]) -> fmt::Result {
    let r0 = limbs[0] as u128;
    let r1 = limbs[1] as u128;
    let r2 = limbs[2] as u128;
    let r3 = limbs[3] as u128;
    let r4 = limbs[4] as u128;

    let l0 = r0 + (r1 << 26) + (r2 << 52) + (r3 << 78);
    let (l0, c) = l0.overflowing_add(r4 << 104);
    let l1 = (r4 >> 24) + if c { 1 } else { 0 };

    write!(f, "0x{:02x}{:032x}", l1, l0)
}

fn write_130_wide(f: &mut fmt::Formatter<'_>, limbs: [u64; 5]) -> fmt::Result {
    let r0 = limbs[0] as u128;
    let r1 = limbs[1] as u128;
    let r2 = limbs[2] as u128;
    let r3 = limbs[3] as u128;
    let r4 = limbs[4] as u128;

    let l0 = r0 + (r1 << 26) + (r2 << 52);
    let (l0, c1) = l0.overflowing_add(r3 << 78);
    let (l0, c2) = l0.overflowing_add(r4 << 104);
    let l1 = (r3 >> 50) + (r4 >> 24) + if c1 { 1 } else { 0 } + if c2 { 1 } else { 0 };

    write!(f, "0x{:02x}{:032x}", l1, l0)
}

#[target_feature(enable = "avx2")]
pub(super) unsafe fn prepare_keys(key: &Key) -> (AdditionKey, PrecomputedMultiplier) {
    let key = _mm256_loadu_si256(key.as_ptr() as *const _);

    let k = AdditionKey(_mm256_and_si256(
        _mm256_permutevar8x32_epi32(key, _mm256_set_epi32(3, 7, 2, 6, 1, 5, 0, 4)),
        _mm256_set_epi32(0, -1, 0, -1, 0, -1, 0, -1),
    ));

    let r = Aligned130::new(_mm256_and_si256(
        key,
        _mm256_set_epi32(0, 0, 0, 0, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc, 0x0fffffff),
    ));

    (k, r.into())
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Aligned130(pub(super) __m256i);

impl fmt::Display for Aligned130 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v0 = [0u8; 32];
        unsafe {
            _mm256_storeu_si256(v0.as_mut_ptr() as *mut _, self.0);
        }

        write!(f, "Aligned130(")?;
        write_130(
            f,
            [
                u32::from_le_bytes(v0[0..4].try_into().unwrap()),
                u32::from_le_bytes(v0[4..8].try_into().unwrap()),
                u32::from_le_bytes(v0[8..12].try_into().unwrap()),
                u32::from_le_bytes(v0[12..16].try_into().unwrap()),
                u32::from_le_bytes(v0[16..20].try_into().unwrap()),
            ],
        )?;
        write!(f, ")")
    }
}

impl Aligned130 {
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn from_block(block: &Block) -> Self {
        Aligned130::new(_mm256_or_si256(
            _mm256_and_si256(
                _mm256_castsi128_si256(_mm_loadu_si128(block.as_ptr() as *const _)),
                _mm256_set_epi64x(0, 0, -1, -1),
            ),
            _mm256_set_epi64x(0, 1, 0, 0),
        ))
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn from_partial_block(block: &Block) -> Self {
        Aligned130::new(_mm256_and_si256(
            _mm256_castsi128_si256(_mm_loadu_si128(block.as_ptr() as *const _)),
            _mm256_set_epi64x(0, 0, -1, -1),
        ))
    }

    #[target_feature(enable = "avx2")]
    unsafe fn new(x: __m256i) -> Self {
        let xl = _mm256_sllv_epi32(x, _mm256_set_epi32(32, 32, 32, 24, 18, 12, 6, 0));

        let xh = _mm256_permutevar8x32_epi32(
            _mm256_srlv_epi32(x, _mm256_set_epi32(32, 32, 32, 2, 8, 14, 20, 26)),
            _mm256_set_epi32(6, 5, 4, 3, 2, 1, 0, 7),
        );

        Aligned130(_mm256_and_si256(
            _mm256_or_si256(xl, xh),
            _mm256_set_epi32(
                0, 0, 0, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff,
            ),
        ))
    }
}

impl Add<Aligned130> for Aligned130 {
    type Output = Aligned130;

    fn add(self, other: Aligned130) -> Aligned130 {
        unsafe { Aligned130(_mm256_add_epi32(self.0, other.0)) }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PrecomputedMultiplier {
    pub(super) a: __m256i,
    pub(super) a_5: __m256i,
}

impl From<Aligned130> for PrecomputedMultiplier {
    fn from(r: Aligned130) -> Self {
        unsafe {
            let a_5 = _mm256_permutevar8x32_epi32(
                _mm256_add_epi32(r.0, _mm256_slli_epi32(r.0, 2)),
                _mm256_set_epi32(4, 3, 2, 1, 1, 1, 1, 1),
            );
            let a = _mm256_blend_epi32(r.0, a_5, 0b11100000);
            let a_5 = _mm256_permute2x128_si256(a_5, a_5, 0);

            PrecomputedMultiplier { a, a_5 }
        }
    }
}

impl Mul<PrecomputedMultiplier> for PrecomputedMultiplier {
    type Output = Unreduced130;

    fn mul(self, other: PrecomputedMultiplier) -> Unreduced130 {
        Aligned130(self.a) * other
    }
}

impl Mul<PrecomputedMultiplier> for Aligned130 {
    type Output = Unreduced130;

    #[inline(always)]
    fn mul(self, other: PrecomputedMultiplier) -> Unreduced130 {
        unsafe {
            let x = self.0;
            let y = other.a;
            let z = other.a_5;

            let v0 = _mm256_mul_epu32(
                _mm256_permutevar8x32_epi32(x, _mm256_set_epi64x(4, 3, 2, 1)),
                _mm256_permutevar8x32_epi32(y, _mm256_set_epi64x(7, 7, 7, 7)),
            );
            let v0 = _mm256_add_epi64(
                v0,
                _mm256_mul_epu32(
                    _mm256_permutevar8x32_epi32(x, _mm256_set_epi64x(3, 2, 1, 0)),
                    _mm256_broadcastd_epi32(_mm256_castsi256_si128(y)),
                ),
            );
            let v0 = _mm256_add_epi64(
                v0,
                _mm256_mul_epu32(
                    _mm256_permutevar8x32_epi32(x, _mm256_set_epi64x(1, 1, 3, 3)),
                    _mm256_permutevar8x32_epi32(y, _mm256_set_epi64x(2, 1, 6, 5)),
                ),
            );
            let v0 = _mm256_add_epi64(
                v0,
                _mm256_mul_epu32(
                    _mm256_permute4x64_epi64(x, set02(1, 0, 0, 2)),
                    _mm256_blend_epi32(
                        _mm256_permutevar8x32_epi32(y, _mm256_set_epi64x(1, 2, 1, 1)),
                        z,
                        0x03,
                    ),
                ),
            );
            let v0 = _mm256_add_epi64(
                v0,
                _mm256_mul_epu32(
                    _mm256_permute4x64_epi64(x, set02(0, 2, 2, 1)),
                    _mm256_permutevar8x32_epi32(y, _mm256_set_epi64x(3, 6, 5, 6)),
                ),
            );

            let v1 = _mm256_mul_epu32(
                _mm256_permutevar8x32_epi32(x, _mm256_set_epi64x(3, 2, 1, 0)),
                _mm256_permutevar8x32_epi32(y, _mm256_set_epi64x(1, 2, 3, 4)),
            );
            let v1 = _mm256_add_epi64(v1, _mm256_permute4x64_epi64(v1, set02(1, 0, 3, 2)));
            let v1 = _mm256_add_epi64(v1, _mm256_permute4x64_epi64(v1, set02(0, 0, 0, 1)));
            let v1 = _mm256_add_epi64(
                v1,
                _mm256_mul_epu32(_mm256_permute4x64_epi64(x, set02(0, 0, 0, 2)), y),
            );

            Unreduced130 { v0, v1 }
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub(super) struct Unreduced130 {
    v0: __m256i,
    v1: __m256i,
}

impl fmt::Display for Unreduced130 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v0 = [0u8; 32];
        let mut v1 = [0u8; 32];
        unsafe {
            _mm256_storeu_si256(v0.as_mut_ptr() as *mut _, self.v0);
            _mm256_storeu_si256(v1.as_mut_ptr() as *mut _, self.v1);
        }

        write!(f, "Unreduced130(")?;
        write_130_wide(
            f,
            [
                u64::from_le_bytes(v0[0..8].try_into().unwrap()),
                u64::from_le_bytes(v0[8..16].try_into().unwrap()),
                u64::from_le_bytes(v0[16..24].try_into().unwrap()),
                u64::from_le_bytes(v0[24..32].try_into().unwrap()),
                u64::from_le_bytes(v1[0..8].try_into().unwrap()),
            ],
        )?;
        write!(f, ")")
    }
}

impl Unreduced130 {
    #[inline(always)]
    pub(super) fn reduce(self) -> Aligned130 {
        unsafe {
            let (red_1, red_0) = adc(self.v1, self.v0);
            let (red_1, red_0) = red(red_1, red_0);
            let (red_1, red_0) = adc(red_1, red_0);

            Aligned130(_mm256_blend_epi32(
                _mm256_permutevar8x32_epi32(red_0, _mm256_set_epi32(0, 6, 4, 0, 6, 4, 2, 0)),
                _mm256_permutevar8x32_epi32(red_1, _mm256_set_epi32(0, 6, 4, 0, 6, 4, 2, 0)),
                0x90,
            ))
        }
    }
}

#[inline(always)]
unsafe fn adc(v1: __m256i, v0: __m256i) -> (__m256i, __m256i) {
    let v0 = _mm256_add_epi64(
        _mm256_and_si256(v0, _mm256_set_epi64x(-1, 0x3ffffff, 0x3ffffff, 0x3ffffff)),
        _mm256_permute4x64_epi64(
            _mm256_srlv_epi64(v0, _mm256_set_epi64x(64, 26, 26, 26)),
            set02(2, 1, 0, 3),
        ),
    );
    let v1 = _mm256_add_epi64(
        v1,
        _mm256_permute4x64_epi64(_mm256_srli_epi64(v0, 26), set02(2, 1, 0, 3)),
    );
    let chain = _mm256_and_si256(v0, _mm256_set_epi64x(0x3ffffff, -1, -1, -1));

    (v1, chain)
}

#[inline(always)]
unsafe fn red(v1: __m256i, v0: __m256i) -> (__m256i, __m256i) {
    let t = _mm256_srlv_epi64(v1, _mm256_set_epi64x(64, 64, 64, 26));
    let red_0 = _mm256_add_epi64(_mm256_add_epi64(v0, t), _mm256_slli_epi64(t, 2));
    let red_1 = _mm256_and_si256(v1, _mm256_set_epi64x(0, 0, 0, 0x3ffffff));
    (red_1, red_0)
}

#[derive(Clone, Debug)]
pub(super) struct Aligned2x130 {
    v0: Aligned130,
    v1: Aligned130,
}

impl fmt::Display for Aligned2x130 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Aligned2x130([")?;
        writeln!(f, "    {},", self.v0)?;
        writeln!(f, "    {},", self.v1)?;
        write!(f, "])")
    }
}

impl Aligned2x130 {
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn from_blocks(src: &[Block; 2]) -> Self {
        Aligned2x130 {
            v0: Aligned130::from_block(&src[0]),
            v1: Aligned130::from_block(&src[1]),
        }
    }

    #[inline(always)]
    pub(super) fn mul_and_sum(
        self,
        r1: PrecomputedMultiplier,
        r2: PrecomputedMultiplier,
    ) -> Unreduced130 {
        unsafe {
            let x = self;
            let r15 = r1.a_5;
            let r25 = r2.a_5;
            let r1 = r1.a;
            let r2 = r2.a;

            let mut v0 = _mm256_mul_epu32(
                _mm256_permutevar8x32_epi32(x.v0.0, _mm256_set_epi64x(4, 3, 2, 1)),
                _mm256_permutevar8x32_epi32(r2, _mm256_set1_epi64x(7)),
            );
            let mut v1 = _mm256_mul_epu32(
                _mm256_permutevar8x32_epi32(x.v1.0, _mm256_set_epi64x(4, 3, 2, 1)),
                _mm256_permutevar8x32_epi32(r1, _mm256_set1_epi64x(7)),
            );

            v0 = _mm256_add_epi64(
                v0,
                _mm256_mul_epu32(
                    _mm256_permute4x64_epi64(x.v0.0, set02(0, 2, 2, 1)),
                    _mm256_permutevar8x32_epi32(r2, _mm256_set_epi64x(3, 6, 5, 6)),
                ),
            );
            v1 = _mm256_add_epi64(
                v1,
                _mm256_mul_epu32(
                    _mm256_permute4x64_epi64(x.v1.0, set02(0, 2, 2, 1)),
                    _mm256_permutevar8x32_epi32(r1, _mm256_set_epi64x(3, 6, 5, 6)),
                ),
            );
            v0 = _mm256_add_epi64(
                v0,
                _mm256_mul_epu32(
                    _mm256_permutevar8x32_epi32(x.v0.0, _mm256_set_epi64x(1, 1, 3, 3)),
                    _mm256_permutevar8x32_epi32(r2, _mm256_set_epi64x(2, 1, 6, 5)),
                ),
            );
            v1 = _mm256_add_epi64(
                v1,
                _mm256_mul_epu32(
                    _mm256_permutevar8x32_epi32(x.v1.0, _mm256_set_epi64x(1, 1, 3, 3)),
                    _mm256_permutevar8x32_epi32(r1, _mm256_set_epi64x(2, 1, 6, 5)),
                ),
            );
            v0 = _mm256_add_epi64(
                v0,
                _mm256_mul_epu32(
                    _mm256_permutevar8x32_epi32(x.v0.0, _mm256_set_epi64x(3, 2, 1, 0)),
                    _mm256_broadcastd_epi32(_mm256_castsi256_si128(r2)),
                ),
            );
            v1 = _mm256_add_epi64(
                v1,
                _mm256_mul_epu32(
                    _mm256_permutevar8x32_epi32(x.v1.0, _mm256_set_epi64x(3, 2, 1, 0)),
                    _mm256_broadcastd_epi32(_mm256_castsi256_si128(r1)),
                ),
            );

            let mut t0 = _mm256_permute4x64_epi64(x.v0.0, set02(1, 0, 0, 2));
            let mut t1 = _mm256_permute4x64_epi64(x.v1.0, set02(1, 0, 0, 2));

            v0 = _mm256_add_epi64(
                v0,
                _mm256_mul_epu32(
                    t0,
                    _mm256_blend_epi32(
                        _mm256_permutevar8x32_epi32(r2, _mm256_set_epi64x(1, 2, 1, 1)),
                        r25,
                        0b00000011,
                    ),
                ),
            );
            v1 = _mm256_add_epi64(
                v1,
                _mm256_mul_epu32(
                    t1,
                    _mm256_blend_epi32(
                        _mm256_permutevar8x32_epi32(r1, _mm256_set_epi64x(1, 2, 1, 1)),
                        r15,
                        0b00000011,
                    ),
                ),
            );
            v0 = _mm256_add_epi64(v0, v1);

            t0 = _mm256_mul_epu32(t0, r2);
            t1 = _mm256_mul_epu32(t1, r1);

            v1 = _mm256_add_epi64(t0, t1);

            t0 = _mm256_mul_epu32(
                _mm256_permutevar8x32_epi32(x.v0.0, _mm256_set_epi64x(3, 2, 1, 0)),
                _mm256_permutevar8x32_epi32(r2, _mm256_set_epi64x(1, 2, 3, 4)),
            );
            t1 = _mm256_mul_epu32(
                _mm256_permutevar8x32_epi32(x.v1.0, _mm256_set_epi64x(3, 2, 1, 0)),
                _mm256_permutevar8x32_epi32(r1, _mm256_set_epi64x(1, 2, 3, 4)),
            );
            t0 = _mm256_add_epi64(t0, t1);
            t0 = _mm256_add_epi64(t0, _mm256_permute4x64_epi64(t0, set02(1, 0, 3, 2)));
            t0 = _mm256_add_epi64(t0, _mm256_permute4x64_epi64(t0, set02(2, 3, 0, 1)));

            v1 = _mm256_add_epi64(v1, t0);

            Unreduced130 { v0, v1 }
        }
    }
}

impl Add<Aligned130> for Aligned2x130 {
    type Output = Aligned2x130;

    fn add(self, other: Aligned130) -> Aligned2x130 {
        Aligned2x130 {
            v0: self.v0 + other,
            v1: self.v1,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub(super) struct SpacedMultiplier4x130 {
    v0: __m256i,
    v1: __m256i,
    r1: PrecomputedMultiplier,
}

impl SpacedMultiplier4x130 {
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn new(
        r1: PrecomputedMultiplier,
        r2: PrecomputedMultiplier,
    ) -> (Self, PrecomputedMultiplier) {
        let r3 = (r2 * r1).reduce();
        let r4 = (r2 * r2).reduce();

        let v0 = _mm256_blend_epi32(
            r3.0,
            _mm256_permutevar8x32_epi32(r2.a, _mm256_set_epi32(4, 3, 1, 0, 0, 0, 0, 0)),
            0b11100000,
        );

        let v1 = _mm256_blend_epi32(
            r4.0,
            _mm256_permutevar8x32_epi32(r2.a, _mm256_set_epi32(4, 2, 0, 0, 0, 0, 0, 0)),
            0b11100000,
        );

        let m = SpacedMultiplier4x130 { v0, v1, r1 };

        (m, r4.into())
    }
}

#[derive(Copy, Clone, Debug)]
pub(super) struct Aligned4x130 {
    v0: __m256i,
    v1: __m256i,
    v2: __m256i,
}

impl fmt::Display for Aligned4x130 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v0 = [0u8; 32];
        let mut v1 = [0u8; 32];
        let mut v2 = [0u8; 32];
        unsafe {
            _mm256_storeu_si256(v0.as_mut_ptr() as *mut _, self.v0);
            _mm256_storeu_si256(v1.as_mut_ptr() as *mut _, self.v1);
            _mm256_storeu_si256(v2.as_mut_ptr() as *mut _, self.v2);
        }

        writeln!(f, "Aligned4x130([")?;
        write!(f, "    ")?;
        write_130(
            f,
            [
                u32::from_le_bytes(v0[0..4].try_into().unwrap()),
                u32::from_le_bytes(v1[0..4].try_into().unwrap()),
                u32::from_le_bytes(v0[4..8].try_into().unwrap()),
                u32::from_le_bytes(v1[4..8].try_into().unwrap()),
                u32::from_le_bytes(v2[0..4].try_into().unwrap()),
            ],
        )?;
        writeln!(f, ",")?;
        write!(f, "    ")?;
        write_130(
            f,
            [
                u32::from_le_bytes(v0[8..12].try_into().unwrap()),
                u32::from_le_bytes(v1[8..12].try_into().unwrap()),
                u32::from_le_bytes(v0[12..16].try_into().unwrap()),
                u32::from_le_bytes(v1[12..16].try_into().unwrap()),
                u32::from_le_bytes(v2[8..12].try_into().unwrap()),
            ],
        )?;
        writeln!(f, ",")?;
        write!(f, "    ")?;
        write_130(
            f,
            [
                u32::from_le_bytes(v0[16..20].try_into().unwrap()),
                u32::from_le_bytes(v1[16..20].try_into().unwrap()),
                u32::from_le_bytes(v0[20..24].try_into().unwrap()),
                u32::from_le_bytes(v1[20..24].try_into().unwrap()),
                u32::from_le_bytes(v2[16..20].try_into().unwrap()),
            ],
        )?;
        writeln!(f, ",")?;
        write!(f, "    ")?;
        write_130(
            f,
            [
                u32::from_le_bytes(v0[24..28].try_into().unwrap()),
                u32::from_le_bytes(v1[24..28].try_into().unwrap()),
                u32::from_le_bytes(v0[28..32].try_into().unwrap()),
                u32::from_le_bytes(v1[28..32].try_into().unwrap()),
                u32::from_le_bytes(v2[24..28].try_into().unwrap()),
            ],
        )?;
        writeln!(f, ",")?;
        write!(f, "])")
    }
}

impl Aligned4x130 {
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn from_blocks(src: &[Block; 4]) -> Self {
        let mask_26 = _mm256_set1_epi32(0x3ffffff);
        let set_hibit = _mm256_set1_epi32(1 << 24);

        let (lo, hi) = src.split_at(2);
        let blocks_23 = _mm256_loadu_si256(hi.as_ptr() as *const _);
        let blocks_01 = _mm256_loadu_si256(lo.as_ptr() as *const _);
        let a0 = _mm256_permute4x64_epi64(
            _mm256_unpackhi_epi64(blocks_01, blocks_23),
            set02(3, 1, 2, 0),
        );
        let a1 = _mm256_permute4x64_epi64(
            _mm256_unpacklo_epi64(blocks_01, blocks_23),
            set02(3, 1, 2, 0),
        );

        let v2 = _mm256_or_si256(_mm256_srli_epi64(a0, 40), set_hibit);

        let a2 = _mm256_or_si256(_mm256_srli_epi64(a1, 46), _mm256_slli_epi64(a0, 18));

        let v1 = _mm256_and_si256(
            _mm256_blend_epi32(_mm256_srli_epi64(a1, 26), a2, 0xAA),
            mask_26,
        );

        let v0 = _mm256_and_si256(
            _mm256_blend_epi32(a1, _mm256_slli_epi64(a2, 26), 0xAA),
            mask_26,
        );

        Aligned4x130 { v0, v1, v2 }
    }
}

impl Add<Aligned4x130> for Aligned4x130 {
    type Output = Aligned4x130;

    #[inline(always)]
    fn add(self, other: Aligned4x130) -> Aligned4x130 {
        unsafe {
            Aligned4x130 {
                v0: _mm256_add_epi32(self.v0, other.v0),
                v1: _mm256_add_epi32(self.v1, other.v1),
                v2: _mm256_add_epi32(self.v2, other.v2),
            }
        }
    }
}

impl Mul<PrecomputedMultiplier> for &Aligned4x130 {
    type Output = Unreduced4x130;

    #[inline(always)]
    fn mul(self, other: PrecomputedMultiplier) -> Unreduced4x130 {
        unsafe {
            let mut x = *self;
            let y = other.a;
            let z = other.a_5;

            let ord = _mm256_set_epi32(6, 7, 4, 5, 2, 3, 0, 1);

            let mut t0 = _mm256_permute4x64_epi64(y, set02(0, 0, 0, 0));
            let mut t1 = _mm256_permute4x64_epi64(y, set02(1, 1, 1, 1));

            let mut v0 = _mm256_mul_epu32(x.v0, t0);
            let mut v1 = _mm256_mul_epu32(x.v1, t0);
            let mut v4 = _mm256_mul_epu32(x.v2, t0);
            let mut v2 = _mm256_mul_epu32(x.v0, t1);
            let mut v3 = _mm256_mul_epu32(x.v1, t1);

            t0 = _mm256_permutevar8x32_epi32(t0, ord);
            t1 = _mm256_permutevar8x32_epi32(t1, ord);

            v1 = _mm256_add_epi64(v1, _mm256_mul_epu32(x.v0, t0));
            v2 = _mm256_add_epi64(v2, _mm256_mul_epu32(x.v1, t0));
            v3 = _mm256_add_epi64(v3, _mm256_mul_epu32(x.v0, t1));
            v4 = _mm256_add_epi64(v4, _mm256_mul_epu32(x.v1, t1));

            let mut t2 = _mm256_permute4x64_epi64(y, set02(2, 2, 2, 2));

            v4 = _mm256_add_epi64(v4, _mm256_mul_epu32(x.v0, t2));

            x.v0 = _mm256_permutevar8x32_epi32(x.v0, ord);
            x.v1 = _mm256_permutevar8x32_epi32(x.v1, ord);
            t2 = _mm256_permutevar8x32_epi32(t2, ord);

            v0 = _mm256_add_epi64(v0, _mm256_mul_epu32(x.v1, t2));
            v1 = _mm256_add_epi64(v1, _mm256_mul_epu32(x.v2, t2));
            v3 = _mm256_add_epi64(v3, _mm256_mul_epu32(x.v0, t0));
            v4 = _mm256_add_epi64(v4, _mm256_mul_epu32(x.v1, t0));

            t0 = _mm256_permutevar8x32_epi32(t0, ord);
            t1 = _mm256_permutevar8x32_epi32(t1, ord);

            v2 = _mm256_add_epi64(v2, _mm256_mul_epu32(x.v0, t0));
            v3 = _mm256_add_epi64(v3, _mm256_mul_epu32(x.v1, t0));
            v4 = _mm256_add_epi64(v4, _mm256_mul_epu32(x.v0, t1));

            t0 = _mm256_permute4x64_epi64(y, set02(3, 3, 3, 3));

            v0 = _mm256_add_epi64(v0, _mm256_mul_epu32(x.v0, t0));
            v1 = _mm256_add_epi64(v1, _mm256_mul_epu32(x.v1, t0));
            v2 = _mm256_add_epi64(v2, _mm256_mul_epu32(x.v2, t0));

            t0 = _mm256_permutevar8x32_epi32(t0, ord);

            v1 = _mm256_add_epi64(v1, _mm256_mul_epu32(x.v0, t0));
            v2 = _mm256_add_epi64(v2, _mm256_mul_epu32(x.v1, t0));
            v3 = _mm256_add_epi64(v3, _mm256_mul_epu32(x.v2, t0));

            x.v1 = _mm256_permutevar8x32_epi32(x.v1, ord);

            v0 = _mm256_add_epi64(v0, _mm256_mul_epu32(x.v1, t0));
            v0 = _mm256_add_epi64(v0, _mm256_mul_epu32(x.v2, z));

            Unreduced4x130 { v0, v1, v2, v3, v4 }
        }
    }
}

impl Mul<SpacedMultiplier4x130> for Aligned4x130 {
    type Output = Unreduced4x130;

    #[inline(always)]
    fn mul(self, m: SpacedMultiplier4x130) -> Unreduced4x130 {
        unsafe {
            let mut x = self;
            let r1 = m.r1.a;

            let v0 = _mm256_unpacklo_epi32(m.v0, m.v1);
            let v1 = _mm256_unpackhi_epi32(m.v0, m.v1);

            let ord = _mm256_set_epi32(1, 0, 6, 7, 2, 0, 3, 1);
            let m_r_0 = _mm256_blend_epi32(
                _mm256_permutevar8x32_epi32(r1, ord),
                _mm256_permutevar8x32_epi32(v0, ord),
                0b00111111,
            );
            let ord = _mm256_set_epi32(3, 2, 4, 5, 2, 0, 3, 1);
            let m_r_2 = _mm256_blend_epi32(
                _mm256_permutevar8x32_epi32(r1, ord),
                _mm256_permutevar8x32_epi32(v1, ord),
                0b00111111,
            );
            let ord = _mm256_set_epi32(1, 4, 6, 6, 2, 4, 3, 5);
            let m_r_4 = _mm256_blend_epi32(
                _mm256_blend_epi32(
                    _mm256_permutevar8x32_epi32(r1, ord),
                    _mm256_permutevar8x32_epi32(v1, ord),
                    0b00010000,
                ),
                _mm256_permutevar8x32_epi32(v0, ord),
                0b00101111,
            );

            let mut v0 = _mm256_mul_epu32(x.v0, m_r_0);
            let mut v1 = _mm256_mul_epu32(x.v1, m_r_0);
            let mut v2 = _mm256_mul_epu32(x.v0, m_r_2);
            let mut v3 = _mm256_mul_epu32(x.v1, m_r_2);
            let mut v4 = _mm256_mul_epu32(x.v0, m_r_4);

            let ord = _mm256_set_epi32(6, 7, 4, 5, 2, 3, 0, 1);
            let m_r_1 = _mm256_permutevar8x32_epi32(m_r_0, ord);
            let m_r_3 = _mm256_permutevar8x32_epi32(m_r_2, ord);

            v1 = _mm256_add_epi64(v1, _mm256_mul_epu32(x.v0, m_r_1));
            v2 = _mm256_add_epi64(v2, _mm256_mul_epu32(x.v1, m_r_1));
            v3 = _mm256_add_epi64(v3, _mm256_mul_epu32(x.v0, m_r_3));
            v4 = _mm256_add_epi64(v4, _mm256_mul_epu32(x.v1, m_r_3));
            v4 = _mm256_add_epi64(v4, _mm256_mul_epu32(x.v2, m_r_0));

            x.v0 = _mm256_permutevar8x32_epi32(x.v0, ord);

            v2 = _mm256_add_epi64(v2, _mm256_mul_epu32(x.v0, m_r_0));
            v3 = _mm256_add_epi64(v3, _mm256_mul_epu32(x.v0, m_r_1));
            v4 = _mm256_add_epi64(v4, _mm256_mul_epu32(x.v0, m_r_2));

            let m_5r_3 = _mm256_add_epi32(m_r_3, _mm256_slli_epi32(m_r_3, 2));
            let m_5r_4 = _mm256_add_epi32(m_r_4, _mm256_slli_epi32(m_r_4, 2));

            v0 = _mm256_add_epi64(v0, _mm256_mul_epu32(x.v0, m_5r_3));
            v0 = _mm256_add_epi64(v0, _mm256_mul_epu32(x.v1, m_5r_4));
            v1 = _mm256_add_epi64(v1, _mm256_mul_epu32(x.v0, m_5r_4));
            v2 = _mm256_add_epi64(v2, _mm256_mul_epu32(x.v2, m_5r_3));
            v3 = _mm256_add_epi64(v3, _mm256_mul_epu32(x.v2, m_5r_4));

            x.v1 = _mm256_permutevar8x32_epi32(x.v1, ord);

            v1 = _mm256_add_epi64(v1, _mm256_mul_epu32(x.v1, m_5r_3));
            v2 = _mm256_add_epi64(v2, _mm256_mul_epu32(x.v1, m_5r_4));
            v3 = _mm256_add_epi64(v3, _mm256_mul_epu32(x.v1, m_r_0));
            v4 = _mm256_add_epi64(v4, _mm256_mul_epu32(x.v1, m_r_1));

            let m_5r_1 = _mm256_permutevar8x32_epi32(m_5r_4, ord);
            let m_5r_2 = _mm256_permutevar8x32_epi32(m_5r_3, ord);

            v0 = _mm256_add_epi64(v0, _mm256_mul_epu32(x.v1, m_5r_2));
            v0 = _mm256_add_epi64(v0, _mm256_mul_epu32(x.v2, m_5r_1));
            v1 = _mm256_add_epi64(v1, _mm256_mul_epu32(x.v2, m_5r_2));

            Unreduced4x130 { v0, v1, v2, v3, v4 }
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Unreduced4x130 {
    v0: __m256i,
    v1: __m256i,
    v2: __m256i,
    v3: __m256i,
    v4: __m256i,
}

impl fmt::Display for Unreduced4x130 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v0 = [0u8; 32];
        let mut v1 = [0u8; 32];
        let mut v2 = [0u8; 32];
        let mut v3 = [0u8; 32];
        let mut v4 = [0u8; 32];
        unsafe {
            _mm256_storeu_si256(v0.as_mut_ptr() as *mut _, self.v0);
            _mm256_storeu_si256(v1.as_mut_ptr() as *mut _, self.v1);
            _mm256_storeu_si256(v2.as_mut_ptr() as *mut _, self.v2);
            _mm256_storeu_si256(v3.as_mut_ptr() as *mut _, self.v3);
            _mm256_storeu_si256(v4.as_mut_ptr() as *mut _, self.v4);
        }

        writeln!(f, "Unreduced4x130([")?;
        write!(f, "    ")?;
        write_130_wide(
            f,
            [
                u64::from_le_bytes(v0[0..8].try_into().unwrap()),
                u64::from_le_bytes(v1[0..8].try_into().unwrap()),
                u64::from_le_bytes(v2[0..8].try_into().unwrap()),
                u64::from_le_bytes(v3[0..8].try_into().unwrap()),
                u64::from_le_bytes(v4[0..8].try_into().unwrap()),
            ],
        )?;
        writeln!(f, ",")?;
        write!(f, "    ")?;
        write_130_wide(
            f,
            [
                u64::from_le_bytes(v0[8..16].try_into().unwrap()),
                u64::from_le_bytes(v1[8..16].try_into().unwrap()),
                u64::from_le_bytes(v2[8..16].try_into().unwrap()),
                u64::from_le_bytes(v3[8..16].try_into().unwrap()),
                u64::from_le_bytes(v4[8..16].try_into().unwrap()),
            ],
        )?;
        writeln!(f, ",")?;
        write!(f, "    ")?;
        write_130_wide(
            f,
            [
                u64::from_le_bytes(v0[16..24].try_into().unwrap()),
                u64::from_le_bytes(v1[16..24].try_into().unwrap()),
                u64::from_le_bytes(v2[16..24].try_into().unwrap()),
                u64::from_le_bytes(v3[16..24].try_into().unwrap()),
                u64::from_le_bytes(v4[16..24].try_into().unwrap()),
            ],
        )?;
        writeln!(f, ",")?;
        write!(f, "    ")?;
        write_130_wide(
            f,
            [
                u64::from_le_bytes(v0[24..32].try_into().unwrap()),
                u64::from_le_bytes(v1[24..32].try_into().unwrap()),
                u64::from_le_bytes(v2[24..32].try_into().unwrap()),
                u64::from_le_bytes(v3[24..32].try_into().unwrap()),
                u64::from_le_bytes(v4[24..32].try_into().unwrap()),
            ],
        )?;
        writeln!(f, ",")?;
        write!(f, "])")
    }
}

impl Unreduced4x130 {
    #[inline(always)]
    pub(super) fn reduce(self) -> Aligned4x130 {
        unsafe {
            let x = self;

            let mask_26 = _mm256_set1_epi64x(0x3ffffff);

            let adc = |x1: __m256i, x0: __m256i| -> (__m256i, __m256i) {
                let y1 = _mm256_add_epi64(x1, _mm256_srli_epi64(x0, 26));
                let y0 = _mm256_and_si256(x0, mask_26);
                (y1, y0)
            };

            let red = |x4: __m256i, x0: __m256i| -> (__m256i, __m256i) {
                let y0 = _mm256_add_epi64(
                    x0,
                    _mm256_mul_epu32(_mm256_srli_epi64(x4, 26), _mm256_set1_epi64x(5)),
                );
                let y4 = _mm256_and_si256(x4, mask_26);
                (y4, y0)
            };

            let (red_1, red_0) = adc(x.v1, x.v0);
            let (red_4, red_3) = adc(x.v4, x.v3);
            let (red_2, red_1) = adc(x.v2, red_1);
            let (red_4, red_0) = red(red_4, red_0);
            let (red_3, red_2) = adc(red_3, red_2);
            let (red_1, red_0) = adc(red_1, red_0);
            let (red_4, red_3) = adc(red_4, red_3);

            Aligned4x130 {
                v0: _mm256_blend_epi32(red_0, _mm256_slli_epi64(red_2, 32), 0b10101010),
                v1: _mm256_blend_epi32(red_1, _mm256_slli_epi64(red_3, 32), 0b10101010),
                v2: red_4,
            }
        }
    }

    #[inline(always)]
    pub(super) fn sum(self) -> Unreduced130 {
        unsafe {
            let x = self;

            let v0 = _mm256_add_epi64(
                _mm256_unpackhi_epi64(x.v0, x.v1),
                _mm256_unpacklo_epi64(x.v0, x.v1),
            );

            let v1 = _mm256_add_epi64(
                _mm256_unpackhi_epi64(x.v2, x.v3),
                _mm256_unpacklo_epi64(x.v2, x.v3),
            );

            let v0 = _mm256_add_epi64(
                _mm256_inserti128_si256(v0, _mm256_castsi256_si128(v1), 1),
                _mm256_inserti128_si256(v1, _mm256_extractf128_si256(v0, 1), 0),
            );

            let v1 = _mm256_add_epi64(x.v4, _mm256_permute4x64_epi64(x.v4, set02(1, 0, 3, 2)));

            let v1 = _mm256_add_epi64(v1, _mm256_permute4x64_epi64(v1, set02(0, 0, 0, 1)));

            Unreduced130 { v0, v1 }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct AdditionKey(__m256i);

impl Add<Aligned130> for AdditionKey {
    type Output = IntegerTag;

    #[inline(always)]
    fn add(self, x: Aligned130) -> IntegerTag {
        unsafe {
            let mut x = _mm256_and_si256(x.0, _mm256_set_epi32(0, 0, 0, -1, -1, -1, -1, -1));
            let k = self.0;

            unsafe fn propagate_carry(x: __m256i) -> __m256i {
                let t = _mm256_permutevar8x32_epi32(
                    _mm256_srli_epi32(x, 26),
                    _mm256_set_epi32(7, 7, 7, 3, 2, 1, 0, 4),
                );

                _mm256_add_epi32(
                    _mm256_add_epi32(
                        _mm256_and_si256(
                            x,
                            _mm256_set_epi32(
                                0, 0, 0, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff,
                            ),
                        ),
                        t,
                    ),
                    _mm256_permutevar8x32_epi32(
                        _mm256_slli_epi32(t, 2),
                        _mm256_set_epi32(7, 7, 7, 7, 7, 7, 7, 0),
                    ),
                )
            }

            for _ in 0..5 {
                x = propagate_carry(x);
            }

            let mut g = _mm256_add_epi32(x, _mm256_set_epi32(0, 0, 0, 0, 0, 0, 0, 5));
            for _ in 0..4 {
                g = propagate_carry(g);
            }
            let g = _mm256_sub_epi32(g, _mm256_set_epi32(0, 0, 0, 1 << 26, 0, 0, 0, 0));

            let mask = _mm256_permutevar8x32_epi32(
                _mm256_sub_epi32(_mm256_srli_epi32(g, 32 - 1), _mm256_set1_epi32(1)),
                _mm256_set1_epi32(4),
            );

            let x = _mm256_or_si256(
                _mm256_and_si256(x, _mm256_xor_si256(mask, _mm256_set1_epi32(-1))),
                _mm256_and_si256(g, mask),
            );

            let x = _mm256_or_si256(
                _mm256_srlv_epi32(x, _mm256_set_epi32(32, 32, 32, 32, 18, 12, 6, 0)),
                _mm256_permutevar8x32_epi32(
                    _mm256_sllv_epi32(x, _mm256_set_epi32(32, 32, 32, 8, 14, 20, 26, 32)),
                    _mm256_set_epi32(7, 7, 7, 7, 4, 3, 2, 1),
                ),
            );

            let mut x = _mm256_add_epi64(
                _mm256_permutevar8x32_epi32(x, _mm256_set_epi32(7, 3, 7, 2, 7, 1, 7, 0)),
                k,
            );

            unsafe fn propagate_carry_32(x: __m256i) -> __m256i {
                _mm256_add_epi64(
                    _mm256_and_si256(x, _mm256_set_epi32(0, -1, 0, -1, 0, -1, 0, -1)),
                    _mm256_permute4x64_epi64(
                        _mm256_and_si256(
                            _mm256_srli_epi64(x, 32),
                            _mm256_set_epi64x(0, -1, -1, -1),
                        ),
                        set02(2, 1, 0, 3),
                    ),
                )
            }
            for _ in 0..3 {
                x = propagate_carry_32(x);
            }

            let x = _mm256_permutevar8x32_epi32(x, _mm256_set_epi32(7, 7, 7, 7, 6, 4, 2, 0));

            IntegerTag(_mm256_castsi256_si128(x))
        }
    }
}

pub(super) struct IntegerTag(__m128i);

impl From<AdditionKey> for IntegerTag {
    fn from(k: AdditionKey) -> Self {
        unsafe {
            IntegerTag(_mm256_castsi256_si128(_mm256_permutevar8x32_epi32(
                k.0,
                _mm256_set_epi32(0, 0, 0, 0, 6, 4, 2, 0),
            )))
        }
    }
}

impl IntegerTag {
    pub(super) fn write(self, tag: &mut [u8]) {
        unsafe {
            _mm_storeu_si128(tag.as_mut_ptr() as *mut _, self.0);
        }
    }
}
