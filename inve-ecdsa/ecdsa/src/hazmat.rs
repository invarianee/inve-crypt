#[cfg(feature = "arithmetic")]
use {
    crate::{Error, RecoveryId, Result, SignatureSize},
    core::borrow::Borrow,
    elliptic_curve::{
        group::Curve as _,
        ops::{Invert, LinearCombination, Reduce},
        subtle::CtOption,
        AffineArithmetic, AffineXCoordinate, Field, FieldBytes, Group, ProjectiveArithmetic,
        ProjectivePoint, Scalar, ScalarArithmetic,
    },
};

#[cfg(feature = "digest")]
use {
    elliptic_curve::FieldSize,
    signature::{digest::Digest, PrehashSignature},
};

#[cfg(any(feature = "arithmetic", feature = "digest"))]
use crate::{
    elliptic_curve::{generic_array::ArrayLength, PrimeCurve},
    Signature,
};

#[cfg(all(feature = "sign"))]
use {
    elliptic_curve::{ff::PrimeField, zeroize::Zeroizing, NonZeroScalar, ScalarCore},
    signature::digest::{
        block_buffer::Eager,
        core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore},
        generic_array::typenum::{IsLess, Le, NonZero, U256},
        FixedOutput, HashMarker, OutputSizeUser,
    },
};

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait SignPrimitive<C>: Field + Into<FieldBytes<C>> + Reduce<C::UInt> + Sized
where
    C: PrimeCurve + ProjectiveArithmetic + ScalarArithmetic<Scalar = Self>,
    SignatureSize<C>: ArrayLength<u8>,
{
    #[allow(non_snake_case)]
    fn try_sign_prehashed<K>(
        &self,
        k: K,
        z: Scalar<C>,
    ) -> Result<(Signature<C>, Option<RecoveryId>)>
    where
        K: Borrow<Self> + Invert<Output = CtOption<Self>>,
    {
        if k.borrow().is_zero().into() {
            return Err(Error::new());
        }

        let k_inv = Option::<Scalar<C>>::from(k.invert()).ok_or_else(Error::new)?;

        let R = (C::ProjectivePoint::generator() * k.borrow()).to_affine();

        let r = Self::from_be_bytes_reduced(R.x());

        let s = k_inv * (z + (r * self));

        if s.is_zero().into() {
            return Err(Error::new());
        }

        Ok((Signature::from_scalars(r, s)?, None))
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait VerifyPrimitive<C>: AffineXCoordinate<C> + Copy + Sized
where
    C: PrimeCurve + AffineArithmetic<AffinePoint = Self> + ProjectiveArithmetic,
    Scalar<C>: Reduce<C::UInt>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify_prehashed(&self, z: Scalar<C>, sig: &Signature<C>) -> Result<()> {
        let (r, s) = sig.split_scalars();
        let s_inv = *s.invert();
        let u1 = z * s_inv;
        let u2 = *r * s_inv;
        let x = ProjectivePoint::<C>::lincomb(
            &ProjectivePoint::<C>::generator(),
            &u1,
            &ProjectivePoint::<C>::from(*self),
            &u2,
        )
        .to_affine()
        .x();

        if Scalar::<C>::from_be_bytes_reduced(x) == *r {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

#[cfg(feature = "digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
pub trait DigestPrimitive: PrimeCurve {
    type Digest: Digest;
}

#[cfg(feature = "digest")]
impl<C> PrehashSignature for Signature<C>
where
    C: DigestPrimitive,
    <FieldSize<C> as core::ops::Add>::Output: ArrayLength<u8>,
{
    type Digest = C::Digest;
}

#[cfg(all(feature = "sign"))]
#[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
pub fn rfc6979_generate_k<C, D>(
    x: &NonZeroScalar<C>,
    z: &Scalar<C>,
    ad: &[u8],
) -> Zeroizing<NonZeroScalar<C>>
where
    C: PrimeCurve + ProjectiveArithmetic,
    D: CoreProxy + FixedOutput<OutputSize = FieldSize<C>>,
    D::Core: BlockSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Clone
        + Default
        + FixedOutputCore
        + HashMarker
        + OutputSizeUser<OutputSize = D::OutputSize>,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let x = Zeroizing::new(ScalarCore::<C>::from(x));
    let k = rfc6979::generate_k::<D, C::UInt>(x.as_uint(), &C::ORDER, &z.to_repr(), ad);
    Zeroizing::new(NonZeroScalar::<C>::from_uint(*k).unwrap())
}
