use crate::{AffinePoint, Secp256k1};

pub type EphemeralSecret = elliptic_curve::ecdh::EphemeralSecret<Secp256k1>;

pub type SharedSecret = elliptic_curve::ecdh::SharedSecret<Secp256k1>;

impl From<&AffinePoint> for SharedSecret {
    fn from(affine: &AffinePoint) -> SharedSecret {
        affine.x.to_bytes().into()
    }
}
