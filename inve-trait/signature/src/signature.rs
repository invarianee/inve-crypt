use crate::error::Error;
use core::fmt::Debug;

#[cfg(feature = "digest-preview")]
#[allow(unused_imports)]
use crate::{
    signer::{DigestSigner, Signer},
    verifier::{DigestVerifier, Verifier},
};

pub trait Signature: AsRef<[u8]> + Debug + Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;

    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

#[cfg(feature = "digest-preview")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest-preview")))]
pub trait PrehashSignature: Signature {
    type Digest: digest::Digest;
}
