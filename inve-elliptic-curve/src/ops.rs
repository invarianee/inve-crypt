pub use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use inve_bigint::{ArrayEncoding, ByteArray, Integer};

#[cfg(feature = "arithmetic")]
use {group::Group, subtle::CtOption};

#[cfg(feature = "digest")]
use digest::FixedOutput;

pub trait Invert {
    type Output;

    fn invert(&self) -> Self::Output;
}

#[cfg(feature = "arithmetic")]
impl<F: ff::Field> Invert for F {
    type Output = CtOption<F>;

    fn invert(&self) -> CtOption<F> {
        ff::Field::invert(self)
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait LinearCombination: Group {
    fn lincomb(x: &Self, k: &Self::Scalar, y: &Self, l: &Self::Scalar) -> Self {
        (*x * k) + (*y * l)
    }
}

pub trait Reduce<UInt: Integer + ArrayEncoding>: Sized {
    fn from_uint_reduced(n: UInt) -> Self;

    fn from_be_bytes_reduced(bytes: ByteArray<UInt>) -> Self {
        Self::from_uint_reduced(UInt::from_be_byte_array(bytes))
    }

    fn from_le_bytes_reduced(bytes: ByteArray<UInt>) -> Self {
        Self::from_uint_reduced(UInt::from_le_byte_array(bytes))
    }

    #[cfg(feature = "digest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
    fn from_be_digest_reduced<D>(digest: D) -> Self
    where
        D: FixedOutput<OutputSize = UInt::ByteSize>,
    {
        Self::from_be_bytes_reduced(digest.finalize_fixed())
    }

    #[cfg(feature = "digest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
    fn from_le_digest_reduced<D>(digest: D) -> Self
    where
        D: FixedOutput<OutputSize = UInt::ByteSize>,
    {
        Self::from_le_bytes_reduced(digest.finalize_fixed())
    }
}

pub trait ReduceNonZero<UInt: Integer + ArrayEncoding>: Sized {
    fn from_uint_reduced_nonzero(n: UInt) -> Self;
}
