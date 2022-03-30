pub use sec1::point::{Coordinates, ModulusSize, Tag};

use crate::{Curve, FieldSize, Result, SecretKey};
use subtle::CtOption;

#[cfg(feature = "arithmetic")]
use crate::{AffinePoint, Error, ProjectiveArithmetic};

pub type EncodedPoint<C> = sec1::point::EncodedPoint<FieldSize<C>>;

pub trait FromEncodedPoint<C>
where
    Self: Sized,
    C: Curve,
    FieldSize<C>: ModulusSize,
{
    fn from_encoded_point(point: &EncodedPoint<C>) -> CtOption<Self>;
}

pub trait ToEncodedPoint<C>
where
    C: Curve,
    FieldSize<C>: ModulusSize,
{
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C>;
}

pub trait ToCompactEncodedPoint<C>
where
    C: Curve,
    FieldSize<C>: ModulusSize,
{
    fn to_compact_encoded_point(&self) -> CtOption<EncodedPoint<C>>;
}

pub trait ValidatePublicKey
where
    Self: Curve,
    FieldSize<Self>: ModulusSize,
{
    #[allow(unused_variables)]
    fn validate_public_key(
        secret_key: &SecretKey<Self>,
        public_key: &EncodedPoint<Self>,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg(all(feature = "arithmetic"))]
impl<C> ValidatePublicKey for C
where
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn validate_public_key(secret_key: &SecretKey<C>, public_key: &EncodedPoint<C>) -> Result<()> {
        let pk = secret_key
            .public_key()
            .to_encoded_point(public_key.is_compressed());

        if public_key == &pk {
            Ok(())
        } else {
            Err(Error)
        }
    }
}
