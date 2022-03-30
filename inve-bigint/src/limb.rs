#![allow(clippy::derive_hash_xor_eq)]

mod add;
mod bit_and;
mod bit_not;
mod bit_or;
mod bit_xor;
mod bits;
mod cmp;
mod encoding;
mod from;
mod mul;
mod sub;

#[cfg(feature = "rand_core")]
mod rand;

use crate::Zero;
use core::fmt;
use subtle::{Choice, ConditionallySelectable};

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("this crate builds on 32-bit and 64-bit platforms only");

#[cfg(target_pointer_width = "32")]
pub type LimbUInt = u32;

#[cfg(target_pointer_width = "32")]
pub(crate) type LimbInt = i32;

#[cfg(target_pointer_width = "32")]
pub type WideLimbUInt = u64;

#[cfg(target_pointer_width = "32")]
pub(crate) type WideLimbInt = i64;

#[cfg(target_pointer_width = "64")]
pub type LimbUInt = u64;

#[cfg(target_pointer_width = "64")]
pub(crate) type LimbInt = i64;

#[cfg(target_pointer_width = "64")]
pub type WideLimbUInt = u128;

#[cfg(target_pointer_width = "64")]
pub(crate) type WideLimbInt = i128;

pub(crate) const HI_BIT: usize = Limb::BIT_SIZE - 1;

#[derive(Copy, Clone, Debug, Default, Hash)]
#[repr(transparent)]
pub struct Limb(pub LimbUInt);

impl Limb {
    pub const ZERO: Self = Limb(0);

    pub const ONE: Self = Limb(1);

    pub const MAX: Self = Limb(LimbUInt::MAX);

    #[cfg(target_pointer_width = "32")]
    pub const BIT_SIZE: usize = 32;
    #[cfg(target_pointer_width = "32")]
    pub const BYTE_SIZE: usize = 4;

    #[cfg(target_pointer_width = "64")]
    pub const BIT_SIZE: usize = 64;
    #[cfg(target_pointer_width = "64")]
    pub const BYTE_SIZE: usize = 8;

    #[inline]
    pub(crate) const fn ct_select(a: Self, b: Self, c: LimbUInt) -> Self {
        Self(a.0 ^ (c & (a.0 ^ b.0)))
    }
}

impl ConditionallySelectable for Limb {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(LimbUInt::conditional_select(&a.0, &b.0, choice))
    }
}

impl Zero for Limb {
    const ZERO: Self = Self::ZERO;
}

impl fmt::Display for Limb {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(self, f)
    }
}

impl fmt::LowerHex for Limb {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for Limb {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl zeroize::DefaultIsZeroes for Limb {}
