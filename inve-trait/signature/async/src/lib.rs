pub use signature::{self, Error, Signature};

#[cfg(feature = "digest")]
pub use signature::digest::{self, Digest};

use async_trait::async_trait;

#[async_trait]
pub trait AsyncSigner<S>
where
    Self: Send + Sync,
    S: Signature + Send + 'static,
{
    async fn sign_async(&self, msg: &[u8]) -> Result<S, Error>;
}

#[async_trait]
impl<S, T> AsyncSigner<S> for T
where
    S: Signature + Send + 'static,
    T: signature::Signer<S> + Send + Sync,
{
    async fn sign_async(&self, msg: &[u8]) -> Result<S, Error> {
        self.try_sign(msg)
    }
}

#[cfg(feature = "digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
#[async_trait]
pub trait AsyncDigestSigner<D, S>
where
    Self: Send + Sync,
    D: Digest + Send + 'static,
    S: Signature + 'static,
{
    async fn sign_digest_async(&self, digest: D) -> Result<S, Error>;
}

#[cfg(feature = "digest")]
#[async_trait]
impl<D, S, T> AsyncDigestSigner<D, S> for T
where
    D: Digest + Send + 'static,
    S: Signature + Send + 'static,
    T: signature::DigestSigner<D, S> + Send + Sync,
{
    async fn sign_digest_async(&self, digest: D) -> Result<S, Error> {
        self.try_sign_digest(digest)
    }
}
