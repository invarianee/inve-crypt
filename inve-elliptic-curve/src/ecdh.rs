use crate::{
    AffineArithmetic, AffinePoint, AffineXCoordinate, Curve, FieldBytes, NonZeroScalar,
    ProjectiveArithmetic, ProjectivePoint, PublicKey,
};
use core::borrow::Borrow;
use group::Curve as _;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub fn diffie_hellman<C>(
    secret_key: impl Borrow<NonZeroScalar<C>>,
    public_key: impl Borrow<AffinePoint<C>>,
) -> SharedSecret<C>
where
    C: Curve + ProjectiveArithmetic,
{
    let public_point = ProjectivePoint::<C>::from(*public_key.borrow());
    let secret_point = (public_point * secret_key.borrow().as_ref()).to_affine();
    SharedSecret::new(secret_point)
}

pub struct EphemeralSecret<C>
where
    C: Curve + ProjectiveArithmetic,
{
    scalar: NonZeroScalar<C>,
}

impl<C> EphemeralSecret<C>
where
    C: Curve + ProjectiveArithmetic,
{
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Self {
            scalar: NonZeroScalar::random(rng),
        }
    }

    pub fn public_key(&self) -> PublicKey<C> {
        PublicKey::from_secret_scalar(&self.scalar)
    }

    pub fn diffie_hellman(&self, public_key: &PublicKey<C>) -> SharedSecret<C> {
        diffie_hellman(&self.scalar, public_key.as_affine())
    }
}

impl<C> From<&EphemeralSecret<C>> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(ephemeral_secret: &EphemeralSecret<C>) -> Self {
        ephemeral_secret.public_key()
    }
}

impl<C> Zeroize for EphemeralSecret<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn zeroize(&mut self) {
        self.scalar.zeroize()
    }
}

impl<C> ZeroizeOnDrop for EphemeralSecret<C> where C: Curve + ProjectiveArithmetic {}

impl<C> Drop for EphemeralSecret<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct SharedSecret<C: Curve> {
    secret_bytes: FieldBytes<C>,
}

impl<C: Curve> SharedSecret<C> {
    #[inline]
    fn new(point: AffinePoint<C>) -> Self
    where
        C: AffineArithmetic,
    {
        Self {
            secret_bytes: point.x(),
        }
    }

    pub fn as_bytes(&self) -> &FieldBytes<C> {
        &self.secret_bytes
    }
}

impl<C: Curve> From<FieldBytes<C>> for SharedSecret<C> {
    fn from(secret_bytes: FieldBytes<C>) -> Self {
        Self { secret_bytes }
    }
}

impl<C: Curve> Zeroize for SharedSecret<C> {
    fn zeroize(&mut self) {
        self.secret_bytes.zeroize()
    }
}

impl<C: Curve> ZeroizeOnDrop for SharedSecret<C> {}

impl<C: Curve> Drop for SharedSecret<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
