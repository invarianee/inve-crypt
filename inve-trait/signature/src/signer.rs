use crate::{error::Error, Signature};

#[cfg(feature = "digest-preview")]
use crate::digest::Digest;

#[cfg(feature = "rand-preview")]
use crate::rand_core::{CryptoRng, RngCore};

pub trait Signer<S: Signature> {
    fn sign(&self, msg: &[u8]) -> S {
        self.try_sign(msg).expect("signature operation failed")
    }

    fn try_sign(&self, msg: &[u8]) -> Result<S, Error>;
}

pub trait SignerMut<S: Signature> {
    fn sign(&mut self, msg: &[u8]) -> S {
        self.try_sign(msg).expect("signature operation failed")
    }

    fn try_sign(&mut self, msg: &[u8]) -> Result<S, Error>;
}

impl<T, S> SignerMut<S> for T
where
    T: Signer<S>,
    S: Signature,
{
    fn try_sign(&mut self, msg: &[u8]) -> Result<S, Error> {
        T::try_sign(self, msg)
    }
}

#[cfg(feature = "digest-preview")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest-preview")))]
pub trait DigestSigner<D, S>
where
    D: Digest,
    S: Signature,
{
    fn sign_digest(&self, digest: D) -> S {
        self.try_sign_digest(digest)
            .expect("signature operation failed")
    }

    fn try_sign_digest(&self, digest: D) -> Result<S, Error>;
}

#[cfg(feature = "rand-preview")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand-preview")))]
pub trait RandomizedSigner<S: Signature> {
    fn sign_with_rng(&self, rng: impl CryptoRng + RngCore, msg: &[u8]) -> S {
        self.try_sign_with_rng(rng, msg)
            .expect("signature operation failed")
    }

    fn try_sign_with_rng(&self, rng: impl CryptoRng + RngCore, msg: &[u8]) -> Result<S, Error>;
}

#[cfg(all(feature = "digest-preview", feature = "rand-preview"))]
#[cfg_attr(docsrs, doc(cfg(feature = "digest-preview")))]
#[cfg_attr(docsrs, doc(cfg(feature = "rand-preview")))]
pub trait RandomizedDigestSigner<D, S>
where
    D: Digest,
    S: Signature,
{
    fn sign_digest_with_rng(&self, rng: impl CryptoRng + RngCore, digest: D) -> S {
        self.try_sign_digest_with_rng(rng, digest)
            .expect("signature operation failed")
    }

    fn try_sign_digest_with_rng(
        &self,
        rng: impl CryptoRng + RngCore,
        digest: D,
    ) -> Result<S, Error>;
}
