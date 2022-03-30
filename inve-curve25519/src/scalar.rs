use core::borrow::Borrow;
use core::cmp::{Eq, PartialEq};
use core::fmt::Debug;
use core::iter::{Product, Sum};
use core::ops::Index;
use core::ops::Neg;
use core::ops::{Add, AddAssign};
use core::ops::{Mul, MulAssign};
use core::ops::{Sub, SubAssign};

#[allow(unused_imports)]
use prelude::*;

use rand_core::{CryptoRng, RngCore};

use digest::generic_array::typenum::U64;
use digest::Digest;

use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use zeroize::Zeroize;

use backend;
use constants;

#[cfg(feature = "fiat_u32_backend")]
type UnpackedScalar = backend::serial::fiat_u32::scalar::Scalar29;
#[cfg(feature = "fiat_u64_backend")]
type UnpackedScalar = backend::serial::fiat_u64::scalar::Scalar52;

#[cfg(feature = "u64_backend")]
type UnpackedScalar = backend::serial::u64::scalar::Scalar52;

#[cfg(feature = "u32_backend")]
type UnpackedScalar = backend::serial::u32::scalar::Scalar29;

#[derive(Copy, Clone, Hash)]
pub struct Scalar {
    pub(crate) bytes: [u8; 32],
}

impl Scalar {
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Scalar {
        let s_unreduced = Scalar { bytes };

        let s = s_unreduced.reduce();
        debug_assert_eq!(0u8, s[31] >> 7);

        s
    }

    pub fn from_bytes_mod_order_wide(input: &[u8; 64]) -> Scalar {
        UnpackedScalar::from_bytes_wide(input).pack()
    }

    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Scalar> {
        if (bytes[31] >> 7) != 0u8 {
            return None;
        }
        let candidate = Scalar::from_bits(bytes);

        if candidate.is_canonical() {
            Some(candidate)
        } else {
            None
        }
    }

    pub const fn from_bits(bytes: [u8; 32]) -> Scalar {
        let mut s = Scalar { bytes };
        s.bytes[31] &= 0b0111_1111;

        s
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Scalar{{\n\tbytes: {:?},\n}}", &self.bytes)
    }
}

impl Eq for Scalar {}
impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl Index<usize> for Scalar {
    type Output = u8;

    fn index(&self, _index: usize) -> &u8 {
        &(self.bytes[_index])
    }
}

impl<'b> MulAssign<&'b Scalar> for Scalar {
    fn mul_assign(&mut self, _rhs: &'b Scalar) {
        *self = UnpackedScalar::mul(&self.unpack(), &_rhs.unpack()).pack();
    }
}

define_mul_assign_variants!(LHS = Scalar, RHS = Scalar);

impl<'a, 'b> Mul<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    fn mul(self, _rhs: &'b Scalar) -> Scalar {
        UnpackedScalar::mul(&self.unpack(), &_rhs.unpack()).pack()
    }
}

define_mul_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl<'b> AddAssign<&'b Scalar> for Scalar {
    fn add_assign(&mut self, _rhs: &'b Scalar) {
        *self = *self + _rhs;
    }
}

define_add_assign_variants!(LHS = Scalar, RHS = Scalar);

impl<'a, 'b> Add<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn add(self, _rhs: &'b Scalar) -> Scalar {
        let sum = UnpackedScalar::add(&self.unpack(), &_rhs.unpack());
        let sum_R = UnpackedScalar::mul_internal(&sum, &constants::R);
        let sum_mod_l = UnpackedScalar::montgomery_reduce(&sum_R);
        sum_mod_l.pack()
    }
}

define_add_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl<'b> SubAssign<&'b Scalar> for Scalar {
    fn sub_assign(&mut self, _rhs: &'b Scalar) {
        *self = *self - _rhs;
    }
}

define_sub_assign_variants!(LHS = Scalar, RHS = Scalar);

impl<'a, 'b> Sub<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn sub(self, rhs: &'b Scalar) -> Scalar {
        let self_R = UnpackedScalar::mul_internal(&self.unpack(), &constants::R);
        let self_mod_l = UnpackedScalar::montgomery_reduce(&self_R);
        let rhs_R = UnpackedScalar::mul_internal(&rhs.unpack(), &constants::R);
        let rhs_mod_l = UnpackedScalar::montgomery_reduce(&rhs_R);

        UnpackedScalar::sub(&self_mod_l, &rhs_mod_l).pack()
    }
}

define_sub_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl<'a> Neg for &'a Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn neg(self) -> Scalar {
        let self_R = UnpackedScalar::mul_internal(&self.unpack(), &constants::R);
        let self_mod_l = UnpackedScalar::montgomery_reduce(&self_R);
        UnpackedScalar::sub(&UnpackedScalar::zero(), &self_mod_l).pack()
    }
}

impl<'a> Neg for Scalar {
    type Output = Scalar;
    fn neg(self) -> Scalar {
        -&self
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::conditional_select(&a.bytes[i], &b.bytes[i], choice);
        }
        Scalar { bytes }
    }
}

#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "serde")]
impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(32)?;
        for byte in self.as_bytes().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScalarVisitor;

        impl<'de> Visitor<'de> for ScalarVisitor {
            type Value = Scalar;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid point in Edwards y + sign format")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Scalar, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 32];
                for i in 0..32 {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or(serde::de::Error::invalid_length(i, &"expected 32 bytes"))?;
                }
                Scalar::from_canonical_bytes(bytes).ok_or(serde::de::Error::custom(
                    &"scalar was not canonically encoded",
                ))
            }
        }

        deserializer.deserialize_tuple(32, ScalarVisitor)
    }
}

impl<T> Product<T> for Scalar
where
    T: Borrow<Scalar>,
{
    fn product<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Scalar::one(), |acc, item| acc * item.borrow())
    }
}

impl<T> Sum<T> for Scalar
where
    T: Borrow<Scalar>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Scalar::zero(), |acc, item| acc + item.borrow())
    }
}

impl Default for Scalar {
    fn default() -> Scalar {
        Scalar::zero()
    }
}

impl From<u8> for Scalar {
    fn from(x: u8) -> Scalar {
        let mut s_bytes = [0u8; 32];
        s_bytes[0] = x;
        Scalar { bytes: s_bytes }
    }
}

impl From<u16> for Scalar {
    fn from(x: u16) -> Scalar {
        use byteorder::{ByteOrder, LittleEndian};
        let mut s_bytes = [0u8; 32];
        LittleEndian::write_u16(&mut s_bytes, x);
        Scalar { bytes: s_bytes }
    }
}

impl From<u32> for Scalar {
    fn from(x: u32) -> Scalar {
        use byteorder::{ByteOrder, LittleEndian};
        let mut s_bytes = [0u8; 32];
        LittleEndian::write_u32(&mut s_bytes, x);
        Scalar { bytes: s_bytes }
    }
}

impl From<u64> for Scalar {
    fn from(x: u64) -> Scalar {
        use byteorder::{ByteOrder, LittleEndian};
        let mut s_bytes = [0u8; 32];
        LittleEndian::write_u64(&mut s_bytes, x);
        Scalar { bytes: s_bytes }
    }
}

impl From<u128> for Scalar {
    fn from(x: u128) -> Scalar {
        use byteorder::{ByteOrder, LittleEndian};
        let mut s_bytes = [0u8; 32];
        LittleEndian::write_u128(&mut s_bytes, x);
        Scalar { bytes: s_bytes }
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Scalar {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

    pub fn hash_from_bytes<D>(input: &[u8]) -> Scalar
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut hash = D::default();
        hash.update(input);
        Scalar::from_hash(hash)
    }

    pub fn from_hash<D>(hash: D) -> Scalar
    where
        D: Digest<OutputSize = U64>,
    {
        let mut output = [0u8; 64];
        output.copy_from_slice(hash.finalize().as_slice());
        Scalar::from_bytes_mod_order_wide(&output)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn zero() -> Self {
        Scalar { bytes: [0u8; 32] }
    }

    pub fn one() -> Self {
        Scalar {
            bytes: [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        }
    }

    pub fn invert(&self) -> Scalar {
        self.unpack().invert().pack()
    }

    #[cfg(feature = "alloc")]
    pub fn batch_invert(inputs: &mut [Scalar]) -> Scalar {
        use zeroize::Zeroizing;

        let n = inputs.len();
        let one: UnpackedScalar = Scalar::one().unpack().to_montgomery();

        let scratch_vec = vec![one; n];
        let mut scratch = Zeroizing::new(scratch_vec);

        let mut acc = Scalar::one().unpack().to_montgomery();

        for (input, scratch) in inputs.iter_mut().zip(scratch.iter_mut()) {
            *scratch = acc;

            let tmp = input.unpack().to_montgomery();
            *input = tmp.pack();
            acc = UnpackedScalar::montgomery_mul(&acc, &tmp);
        }

        debug_assert!(acc.pack() != Scalar::zero());

        acc = acc.montgomery_invert().from_montgomery();

        let ret = acc.pack();

        for (input, scratch) in inputs.iter_mut().rev().zip(scratch.iter().rev()) {
            let tmp = UnpackedScalar::montgomery_mul(&acc, &input.unpack());
            *input = UnpackedScalar::montgomery_mul(&acc, &scratch).pack();
            acc = tmp;
        }

        ret
    }

    pub(crate) fn bits(&self) -> [i8; 256] {
        let mut bits = [0i8; 256];
        for i in 0..256 {
            bits[i] = ((self.bytes[i >> 3] >> (i & 7)) & 1u8) as i8;
        }
        bits
    }

    pub(crate) fn non_adjacent_form(&self, w: usize) -> [i8; 256] {
        debug_assert!(w >= 2);
        debug_assert!(w <= 8);

        use byteorder::{ByteOrder, LittleEndian};

        let mut naf = [0i8; 256];

        let mut x_u64 = [0u64; 5];
        LittleEndian::read_u64_into(&self.bytes, &mut x_u64[0..4]);

        let width = 1 << w;
        let window_mask = width - 1;

        let mut pos = 0;
        let mut carry = 0;
        while pos < 256 {
            let u64_idx = pos / 64;
            let bit_idx = pos % 64;
            let bit_buf: u64;
            if bit_idx < 64 - w {
                bit_buf = x_u64[u64_idx] >> bit_idx;
            } else {
                bit_buf = (x_u64[u64_idx] >> bit_idx) | (x_u64[1 + u64_idx] << (64 - bit_idx));
            }

            let window = carry + (bit_buf & window_mask);

            if window & 1 == 0 {
                pos += 1;
                continue;
            }

            if window < width / 2 {
                carry = 0;
                naf[pos] = window as i8;
            } else {
                carry = 1;
                naf[pos] = (window as i8).wrapping_sub(width as i8);
            }

            pos += w;
        }

        naf
    }

    pub(crate) fn to_radix_16(&self) -> [i8; 64] {
        debug_assert!(self[31] <= 127);
        let mut output = [0i8; 64];

        #[inline(always)]
        fn bot_half(x: u8) -> u8 {
            (x >> 0) & 15
        }
        #[inline(always)]
        fn top_half(x: u8) -> u8 {
            (x >> 4) & 15
        }

        for i in 0..32 {
            output[2 * i] = bot_half(self[i]) as i8;
            output[2 * i + 1] = top_half(self[i]) as i8;
        }
        for i in 0..63 {
            let carry = (output[i] + 8) >> 4;
            output[i] -= carry << 4;
            output[i + 1] += carry;
        }

        output
    }

    pub(crate) fn to_radix_2w_size_hint(w: usize) -> usize {
        debug_assert!(w >= 4);
        debug_assert!(w <= 8);

        let digits_count = match w {
            4 => (256 + w - 1) / w as usize,
            5 => (256 + w - 1) / w as usize,
            6 => (256 + w - 1) / w as usize,
            7 => (256 + w - 1) / w as usize,
            8 => (256 + w - 1) / w + 1 as usize,
            _ => panic!("invalid radix parameter"),
        };

        debug_assert!(digits_count <= 64);
        digits_count
    }

    pub(crate) fn to_radix_2w(&self, w: usize) -> [i8; 64] {
        debug_assert!(w >= 4);
        debug_assert!(w <= 8);

        if w == 4 {
            return self.to_radix_16();
        }

        use byteorder::{ByteOrder, LittleEndian};

        let mut scalar64x4 = [0u64; 4];
        LittleEndian::read_u64_into(&self.bytes, &mut scalar64x4[0..4]);

        let radix: u64 = 1 << w;
        let window_mask: u64 = radix - 1;

        let mut carry = 0u64;
        let mut digits = [0i8; 64];
        let digits_count = (256 + w - 1) / w as usize;
        for i in 0..digits_count {
            let bit_offset = i * w;
            let u64_idx = bit_offset / 64;
            let bit_idx = bit_offset % 64;

            let bit_buf: u64;
            if bit_idx < 64 - w || u64_idx == 3 {
                bit_buf = scalar64x4[u64_idx] >> bit_idx;
            } else {
                bit_buf =
                    (scalar64x4[u64_idx] >> bit_idx) | (scalar64x4[1 + u64_idx] << (64 - bit_idx));
            }

            let coef = carry + (bit_buf & window_mask);

            carry = (coef + (radix / 2) as u64) >> w;
            digits[i] = ((coef as i64) - (carry << w) as i64) as i8;
        }

        match w {
            8 => digits[digits_count] += carry as i8,
            _ => digits[digits_count - 1] += (carry << w) as i8,
        }

        digits
    }

    pub(crate) fn unpack(&self) -> UnpackedScalar {
        UnpackedScalar::from_bytes(&self.bytes)
    }

    #[allow(non_snake_case)]
    pub fn reduce(&self) -> Scalar {
        let x = self.unpack();
        let xR = UnpackedScalar::mul_internal(&x, &constants::R);
        let x_mod_l = UnpackedScalar::montgomery_reduce(&xR);
        x_mod_l.pack()
    }

    pub fn is_canonical(&self) -> bool {
        *self == self.reduce()
    }
}

impl UnpackedScalar {
    fn pack(&self) -> Scalar {
        Scalar {
            bytes: self.to_bytes(),
        }
    }

    pub fn montgomery_invert(&self) -> UnpackedScalar {
        let _1 = self;
        let _10 = _1.montgomery_square();
        let _100 = _10.montgomery_square();
        let _11 = UnpackedScalar::montgomery_mul(&_10, &_1);
        let _101 = UnpackedScalar::montgomery_mul(&_10, &_11);
        let _111 = UnpackedScalar::montgomery_mul(&_10, &_101);
        let _1001 = UnpackedScalar::montgomery_mul(&_10, &_111);
        let _1011 = UnpackedScalar::montgomery_mul(&_10, &_1001);
        let _1111 = UnpackedScalar::montgomery_mul(&_100, &_1011);

        let mut y = UnpackedScalar::montgomery_mul(&_1111, &_1);

        #[inline]
        fn square_multiply(y: &mut UnpackedScalar, squarings: usize, x: &UnpackedScalar) {
            for _ in 0..squarings {
                *y = y.montgomery_square();
            }
            *y = UnpackedScalar::montgomery_mul(y, x);
        }

        square_multiply(&mut y, 123 + 3, &_101);
        square_multiply(&mut y, 2 + 2, &_11);
        square_multiply(&mut y, 1 + 4, &_1111);
        square_multiply(&mut y, 1 + 4, &_1111);
        square_multiply(&mut y, 4, &_1001);
        square_multiply(&mut y, 2, &_11);
        square_multiply(&mut y, 1 + 4, &_1111);
        square_multiply(&mut y, 1 + 3, &_101);
        square_multiply(&mut y, 3 + 3, &_101);
        square_multiply(&mut y, 3, &_111);
        square_multiply(&mut y, 1 + 4, &_1111);
        square_multiply(&mut y, 2 + 3, &_111);
        square_multiply(&mut y, 2 + 2, &_11);
        square_multiply(&mut y, 1 + 4, &_1011);
        square_multiply(&mut y, 2 + 4, &_1011);
        square_multiply(&mut y, 6 + 4, &_1001);
        square_multiply(&mut y, 2 + 2, &_11);
        square_multiply(&mut y, 3 + 2, &_11);
        square_multiply(&mut y, 3 + 2, &_11);
        square_multiply(&mut y, 1 + 4, &_1001);
        square_multiply(&mut y, 1 + 3, &_111);
        square_multiply(&mut y, 2 + 4, &_1111);
        square_multiply(&mut y, 1 + 4, &_1011);
        square_multiply(&mut y, 3, &_101);
        square_multiply(&mut y, 2 + 4, &_1111);
        square_multiply(&mut y, 3, &_101);
        square_multiply(&mut y, 1 + 2, &_11);

        y
    }

    pub fn invert(&self) -> UnpackedScalar {
        self.to_montgomery().montgomery_invert().from_montgomery()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use constants;

    pub static X: Scalar = Scalar {
        bytes: [
            0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84, 0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2,
            0x7d, 0x52, 0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44, 0xd4, 0x49, 0xf4, 0xa8,
            0x79, 0xd9, 0xf2, 0x04,
        ],
    };
    pub static XINV: Scalar = Scalar {
        bytes: [
            0x1c, 0xdc, 0x17, 0xfc, 0xe0, 0xe9, 0xa5, 0xbb, 0xd9, 0x24, 0x7e, 0x56, 0xbb, 0x01,
            0x63, 0x47, 0xbb, 0xba, 0x31, 0xed, 0xd5, 0xa9, 0xbb, 0x96, 0xd5, 0x0b, 0xcd, 0x7a,
            0x3f, 0x96, 0x2a, 0x0f,
        ],
    };
    pub static Y: Scalar = Scalar {
        bytes: [
            0x90, 0x76, 0x33, 0xfe, 0x1c, 0x4b, 0x66, 0xa4, 0xa2, 0x8d, 0x2d, 0xd7, 0x67, 0x83,
            0x86, 0xc3, 0x53, 0xd0, 0xde, 0x54, 0x55, 0xd4, 0xfc, 0x9d, 0xe8, 0xef, 0x7a, 0xc3,
            0x1f, 0x35, 0xbb, 0x05,
        ],
    };

    static X_TIMES_Y: Scalar = Scalar {
        bytes: [
            0x6c, 0x33, 0x74, 0xa1, 0x89, 0x4f, 0x62, 0x21, 0x0a, 0xaa, 0x2f, 0xe1, 0x86, 0xa6,
            0xf9, 0x2c, 0xe0, 0xaa, 0x75, 0xc2, 0x77, 0x95, 0x81, 0xc2, 0x95, 0xfc, 0x08, 0x17,
            0x9a, 0x73, 0x94, 0x0c,
        ],
    };

    static CANONICAL_2_256_MINUS_1: Scalar = Scalar {
        bytes: [
            28, 149, 152, 141, 116, 49, 236, 214, 112, 207, 125, 115, 244, 91, 239, 198, 254, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 15,
        ],
    };

    static A_SCALAR: Scalar = Scalar {
        bytes: [
            0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d, 0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8,
            0x26, 0x4d, 0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1, 0x58, 0x9e, 0x7b, 0x7f,
            0x23, 0x76, 0xef, 0x09,
        ],
    };

    static A_NAF: [i8; 256] = [
        0, 13, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, -11, 0, 0, 0, 0, 3, 0, 0,
        0, 0, 1, 0, 0, 0, 0, 9, 0, 0, 0, 0, -5, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 11, 0, 0, 0, 0,
        11, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, -3, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, -1, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, -15, 0, 0, 0, 0, -7, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 5,
        0, 0, 0, 0, 13, 0, 0, 0, 0, 0, -3, 0, 0, 0, 0, -11, 0, 0, 0, 0, -7, 0, 0, 0, 0, -13, 0, 0,
        0, 0, 11, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, -15, 0, 0, 0, 0, 1, 0, 0, 0, 0,
        7, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 15,
        0, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, -15, 0,
        0, 0, 0, 0, 15, 0, 0, 0, 0, 15, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    ];

    static LARGEST_ED25519_S: Scalar = Scalar {
        bytes: [
            0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    };

    static CANONICAL_LARGEST_ED25519_S_PLUS_ONE: Scalar = Scalar {
        bytes: [
            0x7e, 0x34, 0x47, 0x75, 0x47, 0x4a, 0x7f, 0x97, 0x23, 0xb6, 0x3a, 0x8b, 0xe9, 0x2a,
            0xe7, 0x6d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x0f,
        ],
    };

    static CANONICAL_LARGEST_ED25519_S_MINUS_ONE: Scalar = Scalar {
        bytes: [
            0x7c, 0x34, 0x47, 0x75, 0x47, 0x4a, 0x7f, 0x97, 0x23, 0xb6, 0x3a, 0x8b, 0xe9, 0x2a,
            0xe7, 0x6d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x0f,
        ],
    };

    #[test]
    fn fuzzer_testcase_reduction() {
        let a_bytes = [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let b_bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 210, 210,
            210, 255, 255, 255, 255, 10,
        ];
        let c_bytes = [
            134, 171, 119, 216, 180, 128, 178, 62, 171, 132, 32, 62, 34, 119, 104, 193, 47, 215,
            181, 250, 14, 207, 172, 93, 75, 207, 211, 103, 144, 204, 56, 14,
        ];

        let a = Scalar::from_bytes_mod_order(a_bytes);
        let b = Scalar::from_bytes_mod_order(b_bytes);
        let c = Scalar::from_bytes_mod_order(c_bytes);

        let mut tmp = [0u8; 64];

        tmp[0..32].copy_from_slice(&a_bytes[..]);
        let also_a = Scalar::from_bytes_mod_order_wide(&tmp);

        tmp[0..32].copy_from_slice(&b_bytes[..]);
        let also_b = Scalar::from_bytes_mod_order_wide(&tmp);

        let expected_c = &a * &b;
        let also_expected_c = &also_a * &also_b;

        assert_eq!(c, expected_c);
        assert_eq!(c, also_expected_c);
    }

    #[test]
    fn non_adjacent_form_test_vector() {
        let naf = A_SCALAR.non_adjacent_form(5);
        for i in 0..256 {
            assert_eq!(naf[i], A_NAF[i]);
        }
    }

    fn non_adjacent_form_iter(w: usize, x: &Scalar) {
        let naf = x.non_adjacent_form(w);

        let mut y = Scalar::zero();
        for i in (0..256).rev() {
            y += y;
            let digit = if naf[i] < 0 {
                -Scalar::from((-naf[i]) as u64)
            } else {
                Scalar::from(naf[i] as u64)
            };
            y += digit;
        }

        assert_eq!(*x, y);
    }

    #[test]
    fn non_adjacent_form_random() {
        let mut rng = rand::thread_rng();
        for _ in 0..1_000 {
            let x = Scalar::random(&mut rng);
            for w in &[5, 6, 7, 8] {
                non_adjacent_form_iter(*w, &x);
            }
        }
    }

    #[test]
    fn from_u64() {
        let val: u64 = 0xdeadbeefdeadbeef;
        let s = Scalar::from(val);
        assert_eq!(s[7], 0xde);
        assert_eq!(s[6], 0xad);
        assert_eq!(s[5], 0xbe);
        assert_eq!(s[4], 0xef);
        assert_eq!(s[3], 0xde);
        assert_eq!(s[2], 0xad);
        assert_eq!(s[1], 0xbe);
        assert_eq!(s[0], 0xef);
    }

    #[test]
    fn scalar_mul_by_one() {
        let test_scalar = &X * &Scalar::one();
        for i in 0..32 {
            assert!(test_scalar[i] == X[i]);
        }
    }

    #[test]
    fn add_reduces() {
        assert_eq!(
            (LARGEST_ED25519_S + Scalar::one()).reduce(),
            CANONICAL_LARGEST_ED25519_S_PLUS_ONE
        );
        assert_eq!(
            LARGEST_ED25519_S + Scalar::one(),
            CANONICAL_LARGEST_ED25519_S_PLUS_ONE
        );
    }

    #[test]
    fn sub_reduces() {
        assert_eq!(
            (LARGEST_ED25519_S - Scalar::one()).reduce(),
            CANONICAL_LARGEST_ED25519_S_MINUS_ONE
        );
        assert_eq!(
            LARGEST_ED25519_S - Scalar::one(),
            CANONICAL_LARGEST_ED25519_S_MINUS_ONE
        );
    }

    #[test]
    fn quarkslab_scalar_overflow_does_not_occur() {
        let large_bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];

        let a = Scalar::from_bytes_mod_order(large_bytes);
        let b = Scalar::from_bits(large_bytes);

        assert_eq!(a, b.reduce());

        let a_3 = a + a + a;
        let b_3 = b + b + b;

        assert_eq!(a_3, b_3);

        let neg_a = -a;
        let neg_b = -b;

        assert_eq!(neg_a, neg_b);

        let minus_a_3 = Scalar::zero() - a - a - a;
        let minus_b_3 = Scalar::zero() - b - b - b;

        assert_eq!(minus_a_3, minus_b_3);
        assert_eq!(minus_a_3, -a_3);
        assert_eq!(minus_b_3, -b_3);
    }

    #[test]
    fn impl_add() {
        let two = Scalar::from(2u64);
        let one = Scalar::one();
        let should_be_two = &one + &one;
        assert_eq!(should_be_two, two);
    }

    #[allow(non_snake_case)]
    #[test]
    fn impl_mul() {
        let should_be_X_times_Y = &X * &Y;
        assert_eq!(should_be_X_times_Y, X_TIMES_Y);
    }

    #[allow(non_snake_case)]
    #[test]
    fn impl_product() {
        let X_Y_vector = vec![X, Y];
        let should_be_X_times_Y: Scalar = X_Y_vector.iter().product();
        assert_eq!(should_be_X_times_Y, X_TIMES_Y);

        let one = Scalar::one();
        let empty_vector = vec![];
        let should_be_one: Scalar = empty_vector.iter().product();
        assert_eq!(should_be_one, one);

        let xs = [Scalar::from(2u64); 10];
        let ys = [Scalar::from(3u64); 10];
        let zs = xs.iter().zip(ys.iter()).map(|(x, y)| x * y);

        let x_prod: Scalar = xs.iter().product();
        let y_prod: Scalar = ys.iter().product();
        let z_prod: Scalar = zs.product();

        assert_eq!(x_prod, Scalar::from(1024u64));
        assert_eq!(y_prod, Scalar::from(59049u64));
        assert_eq!(z_prod, Scalar::from(60466176u64));
        assert_eq!(x_prod * y_prod, z_prod);
    }

    #[test]
    fn impl_sum() {
        let two = Scalar::from(2u64);
        let one_vector = vec![Scalar::one(), Scalar::one()];
        let should_be_two: Scalar = one_vector.iter().sum();
        assert_eq!(should_be_two, two);

        let zero = Scalar::zero();
        let empty_vector = vec![];
        let should_be_zero: Scalar = empty_vector.iter().sum();
        assert_eq!(should_be_zero, zero);

        let xs = [Scalar::from(1u64); 10];
        let ys = [Scalar::from(2u64); 10];
        let zs = xs.iter().zip(ys.iter()).map(|(x, y)| x + y);

        let x_sum: Scalar = xs.iter().sum();
        let y_sum: Scalar = ys.iter().sum();
        let z_sum: Scalar = zs.sum();

        assert_eq!(x_sum, Scalar::from(10u64));
        assert_eq!(y_sum, Scalar::from(20u64));
        assert_eq!(z_sum, Scalar::from(30u64));
        assert_eq!(x_sum + y_sum, z_sum);
    }

    #[test]
    fn square() {
        let expected = &X * &X;
        let actual = X.unpack().square().pack();
        for i in 0..32 {
            assert!(expected[i] == actual[i]);
        }
    }

    #[test]
    fn reduce() {
        let biggest = Scalar::from_bytes_mod_order([0xff; 32]);
        assert_eq!(biggest, CANONICAL_2_256_MINUS_1);
    }

    #[test]
    fn from_bytes_mod_order_wide() {
        let mut bignum = [0u8; 64];
        for i in 0..32 {
            bignum[i] = X[i];
            bignum[32 + i] = X[i];
        }
        let reduced = Scalar {
            bytes: [
                216, 154, 179, 139, 210, 121, 2, 71, 69, 99, 158, 216, 23, 173, 63, 100, 204, 0,
                91, 50, 219, 153, 57, 249, 28, 82, 31, 197, 100, 165, 192, 8,
            ],
        };
        let test_red = Scalar::from_bytes_mod_order_wide(&bignum);
        for i in 0..32 {
            assert!(test_red[i] == reduced[i]);
        }
    }

    #[allow(non_snake_case)]
    #[test]
    fn invert() {
        let inv_X = X.invert();
        assert_eq!(inv_X, XINV);
        let should_be_one = &inv_X * &X;
        assert_eq!(should_be_one, Scalar::one());
    }

    #[allow(non_snake_case)]
    #[test]
    fn neg_twice_is_identity() {
        let negative_X = -&X;
        let should_be_X = -&negative_X;

        assert_eq!(should_be_X, X);
    }

    #[test]
    fn to_bytes_from_bytes_roundtrips() {
        let unpacked = X.unpack();
        let bytes = unpacked.to_bytes();
        let should_be_unpacked = UnpackedScalar::from_bytes(&bytes);

        assert_eq!(should_be_unpacked.0, unpacked.0);
    }

    #[test]
    fn montgomery_reduce_matches_from_bytes_mod_order_wide() {
        let mut bignum = [0u8; 64];

        for i in 0..32 {
            bignum[i] = X[i];
            bignum[32 + i] = X[i];
        }
        let expected = Scalar {
            bytes: [
                216, 154, 179, 139, 210, 121, 2, 71, 69, 99, 158, 216, 23, 173, 63, 100, 204, 0,
                91, 50, 219, 153, 57, 249, 28, 82, 31, 197, 100, 165, 192, 8,
            ],
        };
        let reduced = Scalar::from_bytes_mod_order_wide(&bignum);

        assert_eq!(reduced.bytes, expected.bytes);

        let interim =
            UnpackedScalar::mul_internal(&UnpackedScalar::from_bytes_wide(&bignum), &constants::R);
        let montgomery_reduced = UnpackedScalar::montgomery_reduce(&interim);

        assert_eq!(montgomery_reduced.0, reduced.unpack().0);
        assert_eq!(montgomery_reduced.0, expected.unpack().0)
    }

    #[test]
    fn canonical_decoding() {
        let canonical_bytes = [
            99, 99, 99, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];

        let non_canonical_bytes_because_unreduced = [16; 32];

        let non_canonical_bytes_because_highbit = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 128,
        ];

        assert!(Scalar::from_canonical_bytes(canonical_bytes).is_some());
        assert!(Scalar::from_canonical_bytes(non_canonical_bytes_because_unreduced).is_none());
        assert!(Scalar::from_canonical_bytes(non_canonical_bytes_because_highbit).is_none());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_bincode_scalar_roundtrip() {
        use bincode;
        let encoded = bincode::serialize(&X).unwrap();
        let parsed: Scalar = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, X);

        assert_eq!(encoded.len(), 32);

        assert_eq!(X, bincode::deserialize(X.as_bytes()).unwrap(),);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn batch_invert_with_a_zero_input_panics() {
        let mut xs = vec![Scalar::one(); 16];
        xs[3] = Scalar::zero();
        Scalar::batch_invert(&mut xs);
    }

    #[test]
    fn batch_invert_empty() {
        assert_eq!(Scalar::one(), Scalar::batch_invert(&mut []));
    }

    #[test]
    fn batch_invert_consistency() {
        let mut x = Scalar::from(1u64);
        let mut v1: Vec<_> = (0..16)
            .map(|_| {
                let tmp = x;
                x = x + x;
                tmp
            })
            .collect();
        let v2 = v1.clone();

        let expected: Scalar = v1.iter().product();
        let expected = expected.invert();
        let ret = Scalar::batch_invert(&mut v1);
        assert_eq!(ret, expected);

        for (a, b) in v1.iter().zip(v2.iter()) {
            assert_eq!(a * b, Scalar::one());
        }
    }

    fn test_pippenger_radix_iter(scalar: Scalar, w: usize) {
        let digits_count = Scalar::to_radix_2w_size_hint(w);
        let digits = scalar.to_radix_2w(w);

        let radix = Scalar::from((1 << w) as u64);
        let mut term = Scalar::one();
        let mut recovered_scalar = Scalar::zero();
        for digit in &digits[0..digits_count] {
            let digit = *digit;
            if digit != 0 {
                let sdigit = if digit < 0 {
                    -Scalar::from((-(digit as i64)) as u64)
                } else {
                    Scalar::from(digit as u64)
                };
                recovered_scalar += term * sdigit;
            }
            term *= radix;
        }
        assert_eq!(recovered_scalar, scalar.reduce());
    }

    #[test]
    fn test_pippenger_radix() {
        use core::iter;
        let cases = (2..100)
            .map(|s| Scalar::from(s as u64).invert())
            .chain(iter::once(Scalar::from_bits([0xff; 32])));

        for scalar in cases {
            test_pippenger_radix_iter(scalar, 6);
            test_pippenger_radix_iter(scalar, 7);
            test_pippenger_radix_iter(scalar, 8);
        }
    }
}
