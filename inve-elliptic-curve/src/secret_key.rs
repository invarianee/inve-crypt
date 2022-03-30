#[cfg(all(feature = "pkcs8", feature = "sec1"))]
mod pkcs8;

use crate::{Curve, Error, FieldBytes, Result, ScalarCore};
use core::fmt::{self, Debug};
use generic_array::GenericArray;
use inve_bigint::Encoding;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(all(feature = "alloc", feature = "arithmetic"))]
use {
    crate::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        AffinePoint,
    },
    alloc::vec::Vec,
    der::Encodable,
    zeroize::Zeroizing,
};

#[cfg(feature = "arithmetic")]
use crate::{
    rand_core::{CryptoRng, RngCore},
    NonZeroScalar, ProjectiveArithmetic, PublicKey,
};

#[cfg(feature = "jwk")]
use crate::jwk::{JwkEcKey, JwkParameters};

#[cfg(all(feature = "arithmetic", any(feature = "jwk", feature = "pem")))]
use alloc::string::String;

#[cfg(all(feature = "arithmetic", feature = "jwk"))]
use alloc::string::ToString;

#[cfg(feature = "pem")]
use pem_rfc7468 as pem;

#[cfg(feature = "sec1")]
use crate::{
    sec1::{EncodedPoint, ModulusSize, ValidatePublicKey},
    FieldSize,
};

#[cfg(all(docsrs, feature = "pkcs8"))]
use {crate::pkcs8::DecodePrivateKey, core::str::FromStr};

#[cfg(feature = "pem")]
pub(crate) const SEC1_PEM_TYPE_LABEL: &str = "EC PRIVATE KEY";

#[derive(Clone)]
pub struct SecretKey<C: Curve> {
    inner: ScalarCore<C>,
}

impl<C> SecretKey<C>
where
    C: Curve,
{
    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn random(rng: impl CryptoRng + RngCore) -> Self
    where
        C: ProjectiveArithmetic,
    {
        Self {
            inner: NonZeroScalar::<C>::random(rng).into(),
        }
    }

    pub fn new(scalar: ScalarCore<C>) -> Self {
        Self { inner: scalar }
    }

    pub fn as_scalar_core(&self) -> &ScalarCore<C> {
        &self.inner
    }

    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn to_nonzero_scalar(&self) -> NonZeroScalar<C>
    where
        C: Curve + ProjectiveArithmetic,
    {
        self.into()
    }

    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn public_key(&self) -> PublicKey<C>
    where
        C: Curve + ProjectiveArithmetic,
    {
        PublicKey::from_secret_scalar(&self.to_nonzero_scalar())
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != C::UInt::BYTE_SIZE {
            return Err(Error);
        }

        let inner: ScalarCore<C> = Option::from(ScalarCore::from_be_bytes(
            GenericArray::clone_from_slice(bytes),
        ))
        .ok_or(Error)?;

        if inner.is_zero().into() {
            return Err(Error);
        }

        Ok(Self { inner })
    }

    pub fn to_be_bytes(&self) -> FieldBytes<C> {
        self.inner.to_be_bytes()
    }

    #[cfg(all(feature = "sec1"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
    pub fn from_sec1_der(der_bytes: &[u8]) -> Result<Self>
    where
        C: Curve + ValidatePublicKey,
        FieldSize<C>: ModulusSize,
    {
        sec1::EcPrivateKey::try_from(der_bytes)?
            .try_into()
            .map_err(|_| Error)
    }

    #[cfg(all(feature = "alloc", feature = "arithmetic", feature = "sec1"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "alloc", feature = "arithmetic", feature = "sec1")))
    )]
    pub fn to_sec1_der(&self) -> der::Result<Zeroizing<Vec<u8>>>
    where
        C: Curve + ProjectiveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        let mut private_key_bytes = self.to_be_bytes();
        let public_key_bytes = self.public_key().to_encoded_point(false);

        let ec_private_key = Zeroizing::new(
            sec1::EcPrivateKey {
                private_key: &private_key_bytes,
                parameters: None,
                public_key: Some(public_key_bytes.as_bytes()),
            }
            .to_vec()?,
        );

        private_key_bytes.zeroize();

        Ok(ec_private_key)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    pub fn from_sec1_pem(s: &str) -> Result<Self>
    where
        C: Curve + ValidatePublicKey,
        FieldSize<C>: ModulusSize,
    {
        let (label, der_bytes) = pem::decode_vec(s.as_bytes()).map_err(|_| Error)?;

        if label != SEC1_PEM_TYPE_LABEL {
            return Err(Error);
        }

        Self::from_sec1_der(&*der_bytes).map_err(|_| Error)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    pub fn to_pem(&self, line_ending: pem::LineEnding) -> Result<Zeroizing<String>>
    where
        C: Curve + ProjectiveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        self.to_sec1_der()
            .ok()
            .and_then(|der| pem::encode_string(SEC1_PEM_TYPE_LABEL, line_ending, &der).ok())
            .map(Zeroizing::new)
            .ok_or(Error)
    }

    #[cfg(feature = "jwk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn from_jwk(jwk: &JwkEcKey) -> Result<Self>
    where
        C: JwkParameters + ValidatePublicKey,
        FieldSize<C>: ModulusSize,
    {
        Self::try_from(jwk)
    }

    #[cfg(feature = "jwk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn from_jwk_str(jwk: &str) -> Result<Self>
    where
        C: JwkParameters + ValidatePublicKey,
        FieldSize<C>: ModulusSize,
    {
        jwk.parse::<JwkEcKey>().and_then(|jwk| Self::from_jwk(&jwk))
    }

    #[cfg(all(feature = "arithmetic", feature = "jwk"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn to_jwk(&self) -> JwkEcKey
    where
        C: Curve + JwkParameters + ProjectiveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        self.into()
    }

    #[cfg(all(feature = "arithmetic", feature = "jwk"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn to_jwk_string(&self) -> Zeroizing<String>
    where
        C: Curve + JwkParameters + ProjectiveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        Zeroizing::new(self.to_jwk().to_string())
    }
}

impl<C> ConstantTimeEq for SecretKey<C>
where
    C: Curve,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl<C> Debug for SecretKey<C>
where
    C: Curve,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey<{:?}>{{ ... }}", C::default())
    }
}

impl<C> ZeroizeOnDrop for SecretKey<C> where C: Curve {}

impl<C> Drop for SecretKey<C>
where
    C: Curve,
{
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<C: Curve> Eq for SecretKey<C> {}

impl<C> PartialEq for SecretKey<C>
where
    C: Curve,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(all(feature = "sec1"))]
#[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
impl<C> TryFrom<sec1::EcPrivateKey<'_>> for SecretKey<C>
where
    C: Curve + ValidatePublicKey,
    FieldSize<C>: ModulusSize,
{
    type Error = der::Error;

    fn try_from(sec1_private_key: sec1::EcPrivateKey<'_>) -> der::Result<Self> {
        let secret_key = Self::from_be_bytes(sec1_private_key.private_key)
            .map_err(|_| der::Tag::Sequence.value_error())?;

        if let Some(pk_bytes) = sec1_private_key.public_key {
            let pk = EncodedPoint::<C>::from_bytes(pk_bytes)
                .map_err(|_| der::Tag::BitString.value_error())?;

            if C::validate_public_key(&secret_key, &pk).is_err() {
                return Err(der::Tag::BitString.value_error());
            }
        }

        Ok(secret_key)
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
impl<C> From<NonZeroScalar<C>> for SecretKey<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(scalar: NonZeroScalar<C>) -> SecretKey<C> {
        SecretKey::from(&scalar)
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
impl<C> From<&NonZeroScalar<C>> for SecretKey<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(scalar: &NonZeroScalar<C>) -> SecretKey<C> {
        SecretKey {
            inner: scalar.into(),
        }
    }
}
