#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

#[cfg(feature = "stream")]
#[cfg_attr(docsrs, doc(cfg(feature = "stream")))]
pub mod stream;

pub use generic_array::{self, typenum::consts};

#[cfg(feature = "bytes")]
#[cfg_attr(docsrs, doc(cfg(feature = "bytes")))]
pub use bytes;

#[cfg(feature = "heapless")]
#[cfg_attr(docsrs, doc(cfg(feature = "heapless")))]
pub use heapless;

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub use rand_core;

use core::fmt;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "bytes")]
use bytes::BytesMut;

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error;

pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("aead::Error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub type Key<A> = GenericArray<u8, <A as NewAead>::KeySize>;

pub type Nonce<A> = GenericArray<u8, <A as AeadCore>::NonceSize>;

pub type Tag<A> = GenericArray<u8, <A as AeadCore>::TagSize>;

pub trait NewAead {
    type KeySize: ArrayLength<u8>;

    fn new(key: &Key<Self>) -> Self;

    fn new_from_slice(key: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        if key.len() != Self::KeySize::to_usize() {
            Err(Error)
        } else {
            Ok(Self::new(GenericArray::from_slice(key)))
        }
    }

    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> Key<Self> {
        let mut key = Key::<Self>::default();
        rng.fill_bytes(&mut key);
        key
    }
}

pub trait AeadCore {
    type NonceSize: ArrayLength<u8>;

    type TagSize: ArrayLength<u8>;

    type CiphertextOverhead: ArrayLength<u8> + Unsigned;
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub trait Aead: AeadCore {
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>>;

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>>;
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub trait AeadMut: AeadCore {
    fn encrypt<'msg, 'aad>(
        &mut self,
        nonce: &Nonce<Self>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>>;

    fn decrypt<'msg, 'aad>(
        &mut self,
        nonce: &Nonce<Self>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>>;
}

macro_rules! impl_decrypt_in_place {
    ($aead:expr, $nonce:expr, $aad:expr, $buffer:expr) => {{
        if $buffer.len() < Self::TagSize::to_usize() {
            return Err(Error);
        }

        let tag_pos = $buffer.len() - Self::TagSize::to_usize();
        let (msg, tag) = $buffer.as_mut().split_at_mut(tag_pos);
        $aead.decrypt_in_place_detached($nonce, $aad, msg, Tag::<Self>::from_slice(tag))?;
        $buffer.truncate(tag_pos);
        Ok(())
    }};
}

pub trait AeadInPlace: AeadCore {
    fn encrypt_in_place(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let tag = self.encrypt_in_place_detached(nonce, associated_data, buffer.as_mut())?;
        buffer.extend_from_slice(tag.as_slice())?;
        Ok(())
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>>;

    fn decrypt_in_place(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        impl_decrypt_in_place!(self, nonce, associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()>;
}

pub trait AeadMutInPlace: AeadCore {
    fn encrypt_in_place(
        &mut self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<()> {
        let tag = self.encrypt_in_place_detached(nonce, associated_data, buffer.as_mut())?;
        buffer.extend_from_slice(tag.as_slice())?;
        Ok(())
    }

    fn encrypt_in_place_detached(
        &mut self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>>;

    fn decrypt_in_place(
        &mut self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<()> {
        impl_decrypt_in_place!(self, nonce, associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &mut self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()>;
}

#[cfg(feature = "alloc")]
impl<Alg: AeadInPlace> Aead for Alg {
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let payload = plaintext.into();
        let mut buffer = Vec::with_capacity(payload.msg.len() + Self::TagSize::to_usize());
        buffer.extend_from_slice(payload.msg);
        self.encrypt_in_place(nonce, payload.aad, &mut buffer)?;
        Ok(buffer)
    }

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let payload = ciphertext.into();
        let mut buffer = Vec::from(payload.msg);
        self.decrypt_in_place(nonce, payload.aad, &mut buffer)?;
        Ok(buffer)
    }
}

#[cfg(feature = "alloc")]
impl<Alg: AeadMutInPlace> AeadMut for Alg {
    fn encrypt<'msg, 'aad>(
        &mut self,
        nonce: &Nonce<Self>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let payload = plaintext.into();
        let mut buffer = Vec::with_capacity(payload.msg.len() + Self::TagSize::to_usize());
        buffer.extend_from_slice(payload.msg);
        self.encrypt_in_place(nonce, payload.aad, &mut buffer)?;
        Ok(buffer)
    }

    fn decrypt<'msg, 'aad>(
        &mut self,
        nonce: &Nonce<Self>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let payload = ciphertext.into();
        let mut buffer = Vec::from(payload.msg);
        self.decrypt_in_place(nonce, payload.aad, &mut buffer)?;
        Ok(buffer)
    }
}

impl<Alg: AeadInPlace> AeadMutInPlace for Alg {
    fn encrypt_in_place(
        &mut self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<()> {
        <Self as AeadInPlace>::encrypt_in_place(self, nonce, associated_data, buffer)
    }

    fn encrypt_in_place_detached(
        &mut self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>> {
        <Self as AeadInPlace>::encrypt_in_place_detached(self, nonce, associated_data, buffer)
    }

    fn decrypt_in_place(
        &mut self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<()> {
        <Self as AeadInPlace>::decrypt_in_place(self, nonce, associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &mut self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()> {
        <Self as AeadInPlace>::decrypt_in_place_detached(self, nonce, associated_data, buffer, tag)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct Payload<'msg, 'aad> {
    pub msg: &'msg [u8],

    pub aad: &'aad [u8],
}

#[cfg(feature = "alloc")]
impl<'msg, 'aad> From<&'msg [u8]> for Payload<'msg, 'aad> {
    fn from(msg: &'msg [u8]) -> Self {
        Self { msg, aad: b"" }
    }
}

pub trait Buffer: AsRef<[u8]> + AsMut<[u8]> {
    fn len(&self) -> usize {
        self.as_ref().len()
    }

    fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()>;

    fn truncate(&mut self, len: usize);
}

#[cfg(feature = "alloc")]
impl Buffer for Vec<u8> {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        Vec::extend_from_slice(self, other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len);
    }
}

#[cfg(feature = "bytes")]
impl Buffer for BytesMut {
    fn len(&self) -> usize {
        BytesMut::len(self)
    }

    fn is_empty(&self) -> bool {
        BytesMut::is_empty(self)
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        BytesMut::extend_from_slice(self, other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        BytesMut::truncate(self, len);
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize> Buffer for heapless::Vec<u8, N> {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        heapless::Vec::extend_from_slice(self, other).map_err(|_| Error)
    }

    fn truncate(&mut self, len: usize) {
        heapless::Vec::truncate(self, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    type DynAeadInPlace<N, T, O> =
        dyn AeadInPlace<NonceSize = N, TagSize = T, CiphertextOverhead = O>;

    #[allow(dead_code)]
    type DynAeadMutInPlace<N, T, O> =
        dyn AeadMutInPlace<NonceSize = N, TagSize = T, CiphertextOverhead = O>;
}
