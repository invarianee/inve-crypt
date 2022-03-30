use crate::{
    ops::LinearCombination, AffineXCoordinate, Curve, FieldBytes, IsHigh, PrimeCurve, ScalarCore,
};
use core::fmt::Debug;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::DefaultIsZeroes;

#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait AffineArithmetic: Curve + ScalarArithmetic {
    type AffinePoint: 'static
        + AffineXCoordinate<Self>
        + Copy
        + Clone
        + ConditionallySelectable
        + ConstantTimeEq
        + Debug
        + Default
        + DefaultIsZeroes
        + Eq
        + PartialEq
        + Sized
        + Send
        + Sync;
}

#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait PrimeCurveArithmetic:
    PrimeCurve + ProjectiveArithmetic<ProjectivePoint = Self::CurveGroup>
{
    type CurveGroup: group::prime::PrimeCurve<Affine = <Self as AffineArithmetic>::AffinePoint>;
}

#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait ProjectiveArithmetic: Curve + AffineArithmetic {
    type ProjectivePoint: ConditionallySelectable
        + ConstantTimeEq
        + Default
        + DefaultIsZeroes
        + From<Self::AffinePoint>
        + Into<Self::AffinePoint>
        + LinearCombination
        + group::Curve<AffineRepr = Self::AffinePoint>
        + group::Group<Scalar = Self::Scalar>;
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait ScalarArithmetic: Curve {
    type Scalar: DefaultIsZeroes
        + From<ScalarCore<Self>>
        + Into<FieldBytes<Self>>
        + Into<Self::UInt>
        + IsHigh
        + ff::Field
        + ff::PrimeField<Repr = FieldBytes<Self>>;
}
