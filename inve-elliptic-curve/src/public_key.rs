use crate::{
    AffinePoint, Curve, Error, NonZeroScalar, ProjectiveArithmetic, ProjectivePoint, Result,
};
use core::fmt::Debug;
use group::{Curve as _, Group};

#[cfg(feature = "jwk")]
use crate::{JwkEcKey, JwkParameters};

#[cfg(all(feature = "sec1", feature = "pkcs8"))]
use crate::{
    pkcs8::{self, DecodePublicKey},
    AlgorithmParameters, ALGORITHM_OID,
};

#[cfg(feature = "pem")]
use {core::str::FromStr, pkcs8::EncodePublicKey};

#[cfg(feature = "sec1")]
use {
    crate::{
        sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
        FieldSize, PointCompression,
    },
    core::cmp::Ordering,
    subtle::CtOption,
};

#[cfg(any(feature = "jwk", feature = "pem"))]
use alloc::string::{String, ToString};

#[cfg(all(feature = "alloc", feature = "serde"))]
use serde::{de, ser, Deserialize, Serialize};

#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
{
    point: AffinePoint<C>,
}

impl<C> PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
{
    pub fn from_affine(point: AffinePoint<C>) -> Result<Self> {
        if ProjectivePoint::<C>::from(point).is_identity().into() {
            Err(Error)
        } else {
            Ok(Self { point })
        }
    }

    pub fn from_secret_scalar(scalar: &NonZeroScalar<C>) -> Self {
        Self {
            point: (C::ProjectivePoint::generator() * scalar.as_ref()).to_affine(),
        }
    }

    #[cfg(feature = "sec1")]
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self>
    where
        C: Curve,
        FieldSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    {
        let point = EncodedPoint::<C>::from_bytes(bytes).map_err(|_| Error)?;
        Option::from(Self::from_encoded_point(&point)).ok_or(Error)
    }

    pub fn as_affine(&self) -> &AffinePoint<C> {
        &self.point
    }

    pub fn to_projective(&self) -> ProjectivePoint<C> {
        self.point.into()
    }

    #[cfg(feature = "jwk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn from_jwk(jwk: &JwkEcKey) -> Result<Self>
    where
        C: Curve + JwkParameters,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        jwk.to_public_key::<C>()
    }

    #[cfg(feature = "jwk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn from_jwk_str(jwk: &str) -> Result<Self>
    where
        C: Curve + JwkParameters,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        jwk.parse::<JwkEcKey>().and_then(|jwk| Self::from_jwk(&jwk))
    }

    #[cfg(feature = "jwk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn to_jwk(&self) -> JwkEcKey
    where
        C: Curve + JwkParameters,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        self.into()
    }

    #[cfg(feature = "jwk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn to_jwk_string(&self) -> String
    where
        C: Curve + JwkParameters,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        self.to_jwk().to_string()
    }
}

impl<C> AsRef<AffinePoint<C>> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn as_ref(&self) -> &AffinePoint<C> {
        self.as_affine()
    }
}

impl<C> Copy for PublicKey<C> where C: Curve + ProjectiveArithmetic {}

#[cfg(feature = "sec1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
impl<C> FromEncodedPoint<C> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn from_encoded_point(encoded_point: &EncodedPoint<C>) -> CtOption<Self> {
        AffinePoint::<C>::from_encoded_point(encoded_point).and_then(|point| {
            let is_identity = ProjectivePoint::<C>::from(point).is_identity();
            CtOption::new(PublicKey { point }, !is_identity)
        })
    }
}

#[cfg(feature = "sec1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
impl<C> ToEncodedPoint<C> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C> {
        self.point.to_encoded_point(compress)
    }
}

#[cfg(feature = "sec1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
impl<C> From<PublicKey<C>> for EncodedPoint<C>
where
    C: Curve + ProjectiveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn from(public_key: PublicKey<C>) -> EncodedPoint<C> {
        EncodedPoint::<C>::from(&public_key)
    }
}

#[cfg(feature = "sec1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
impl<C> From<&PublicKey<C>> for EncodedPoint<C>
where
    C: Curve + ProjectiveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn from(public_key: &PublicKey<C>) -> EncodedPoint<C> {
        public_key.to_encoded_point(C::COMPRESS_POINTS)
    }
}

#[cfg(feature = "sec1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
impl<C> PartialOrd for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "sec1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
impl<C> Ord for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_encoded_point(false)
            .cmp(&other.to_encoded_point(false))
    }
}

#[cfg(all(feature = "pkcs8", feature = "sec1"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "pkcs8", feature = "sec1"))))]
impl<C> TryFrom<pkcs8::SubjectPublicKeyInfo<'_>> for PublicKey<C>
where
    C: Curve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    type Error = pkcs8::spki::Error;

    fn try_from(spki: pkcs8::SubjectPublicKeyInfo<'_>) -> pkcs8::spki::Result<Self> {
        spki.algorithm.assert_oids(ALGORITHM_OID, C::OID)?;
        Self::from_sec1_bytes(spki.subject_public_key)
            .map_err(|_| der::Tag::BitString.value_error().into())
    }
}

#[cfg(all(feature = "pkcs8", feature = "sec1"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "pkcs8", feature = "sec1"))))]
impl<C> DecodePublicKey for PublicKey<C>
where
    C: Curve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<C> EncodePublicKey for PublicKey<C>
where
    C: Curve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn to_public_key_der(&self) -> pkcs8::spki::Result<pkcs8::PublicKeyDocument> {
        let public_key_bytes = self.to_encoded_point(false);

        pkcs8::SubjectPublicKeyInfo {
            algorithm: C::algorithm_identifier(),
            subject_public_key: public_key_bytes.as_ref(),
        }
        .try_into()
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<C> FromStr for PublicKey<C>
where
    C: Curve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_public_key_pem(s).map_err(|_| Error)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<C> ToString for PublicKey<C>
where
    C: Curve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn to_string(&self) -> String {
        self.to_public_key_pem(Default::default())
            .expect("PEM encoding error")
    }
}

#[cfg(all(feature = "alloc", feature = "serde"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "alloc", feature = "serde"))))]
impl<C> Serialize for PublicKey<C>
where
    C: Curve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let der = self.to_public_key_der().map_err(ser::Error::custom)?;

        if serializer.is_human_readable() {
            base16ct::upper::encode_string(der.as_ref()).serialize(serializer)
        } else {
            der.as_ref().serialize(serializer)
        }
    }
}

#[cfg(all(feature = "alloc", feature = "serde"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "alloc", feature = "serde"))))]
impl<'de, C> Deserialize<'de> for PublicKey<C>
where
    C: Curve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        use de::Error;

        if deserializer.is_human_readable() {
            let der_bytes = base16ct::mixed::decode_vec(<&str>::deserialize(deserializer)?)
                .map_err(D::Error::custom)?;
            Self::from_public_key_der(&der_bytes)
        } else {
            let der_bytes = <&[u8]>::deserialize(deserializer)?;
            Self::from_public_key_der(der_bytes)
        }
        .map_err(D::Error::custom)
    }
}

#[cfg(all(feature = "dev", test))]
mod tests {
    use crate::{dev::MockCurve, sec1::FromEncodedPoint};

    type EncodedPoint = crate::sec1::EncodedPoint<MockCurve>;
    type PublicKey = super::PublicKey<MockCurve>;

    #[test]
    fn from_encoded_point_rejects_identity() {
        let identity = EncodedPoint::identity();
        assert!(bool::from(
            PublicKey::from_encoded_point(&identity).is_none()
        ));
    }
}
