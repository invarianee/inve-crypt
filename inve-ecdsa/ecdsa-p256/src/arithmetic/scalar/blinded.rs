use super::Scalar;
use core::borrow::Borrow;
use elliptic_curve::{
    group::ff::Field,
    ops::Invert,
    rand_core::{CryptoRng, RngCore},
    subtle::CtOption,
    zeroize::Zeroize,
};

#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct BlindedScalar {
    scalar: Scalar,

    mask: Scalar,
}

impl BlindedScalar {
    pub fn new(scalar: Scalar, rng: impl CryptoRng + RngCore) -> Self {
        Self {
            scalar,
            mask: Scalar::random(rng),
        }
    }
}

impl Borrow<Scalar> for BlindedScalar {
    fn borrow(&self) -> &Scalar {
        &self.scalar
    }
}

impl Invert for BlindedScalar {
    type Output = CtOption<Scalar>;

    fn invert(&self) -> CtOption<Scalar> {
        (self.scalar * self.mask)
            .invert_vartime()
            .map(|s| s * self.mask)
    }
}

impl Zeroize for BlindedScalar {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
        self.mask.zeroize();
    }
}

impl Drop for BlindedScalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}
