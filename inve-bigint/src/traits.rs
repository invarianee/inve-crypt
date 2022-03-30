use crate::{Limb, NonZero};
use core::fmt::Debug;
use core::ops::{BitAnd, BitOr, BitXor, Div, Not, Rem, Shl, Shr};
use subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
    CtOption,
};

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

pub trait Integer:
    'static
    + AsRef<[Limb]>
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + for<'a> CheckedAdd<&'a Self, Output = Self>
    + for<'a> CheckedSub<&'a Self, Output = Self>
    + for<'a> CheckedMul<&'a Self, Output = Self>
    + Copy
    + ConditionallySelectable
    + ConstantTimeEq
    + ConstantTimeGreater
    + ConstantTimeLess
    + Debug
    + Default
    + Div<NonZero<Self>, Output = Self>
    + Eq
    + From<u64>
    + Not
    + Ord
    + Rem<NonZero<Self>, Output = Self>
    + Send
    + Sized
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Sync
    + Zero
{
    const ONE: Self;

    const MAX: Self;

    fn is_odd(&self) -> Choice;

    fn is_even(&self) -> Choice {
        !self.is_odd()
    }
}

pub trait Zero: ConstantTimeEq + Sized {
    const ZERO: Self;

    fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }
}

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub trait Random: Sized {
    fn random(rng: impl CryptoRng + RngCore) -> Self;
}

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub trait RandomMod: Sized + Zero {
    fn random_mod(rng: impl CryptoRng + RngCore, modulus: &NonZero<Self>) -> Self;
}

pub trait AddMod<Rhs = Self> {
    type Output;

    fn add_mod(&self, rhs: &Rhs, p: &Self) -> Self::Output;
}

pub trait SubMod<Rhs = Self> {
    type Output;

    fn sub_mod(&self, rhs: &Rhs, p: &Self) -> Self::Output;
}

pub trait NegMod {
    type Output;

    #[must_use]
    fn neg_mod(&self, p: &Self) -> Self::Output;
}

pub trait MulMod<Rhs = Self> {
    type Output;

    fn mul_mod(&self, rhs: &Rhs, p: &Self, p_inv: Limb) -> Self::Output;
}

pub trait CheckedAdd<Rhs = Self>: Sized {
    type Output;

    fn checked_add(&self, rhs: Rhs) -> CtOption<Self>;
}

pub trait CheckedMul<Rhs = Self>: Sized {
    type Output;

    fn checked_mul(&self, rhs: Rhs) -> CtOption<Self>;
}

pub trait CheckedSub<Rhs = Self>: Sized {
    type Output;

    fn checked_sub(&self, rhs: Rhs) -> CtOption<Self>;
}

pub trait Concat<Rhs = Self> {
    type Output;

    fn concat(&self, rhs: &Self) -> Self::Output;
}

pub trait Split<Rhs = Self> {
    type Output;

    fn split(&self) -> (Self::Output, Self::Output);
}

pub trait Encoding: Sized {
    const BIT_SIZE: usize;

    const BYTE_SIZE: usize;

    type Repr: AsRef<[u8]> + AsMut<[u8]> + Copy + Clone + Sized;

    fn from_be_bytes(bytes: Self::Repr) -> Self;

    fn from_le_bytes(bytes: Self::Repr) -> Self;

    fn to_be_bytes(&self) -> Self::Repr;

    fn to_le_bytes(&self) -> Self::Repr;
}
