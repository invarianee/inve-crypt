use crate::{AffinePoint, NistP256};

pub type EphemeralSecret = elliptic_curve::ecdh::EphemeralSecret<NistP256>;

pub type SharedSecret = elliptic_curve::ecdh::SharedSecret<NistP256>;

impl From<&AffinePoint> for SharedSecret {
    fn from(affine: &AffinePoint) -> SharedSecret {
        affine.x.to_bytes().into()
    }
}
