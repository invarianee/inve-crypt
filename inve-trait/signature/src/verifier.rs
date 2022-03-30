use crate::{error::Error, Signature};

#[cfg(feature = "digest-preview")]
use crate::digest::Digest;

pub trait Verifier<S: Signature> {
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error>;
}

#[cfg(feature = "digest-preview")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest-preview")))]
pub trait DigestVerifier<D, S>
where
    D: Digest,
    S: Signature,
{
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), Error>;
}
