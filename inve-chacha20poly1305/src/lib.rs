mod cipher;

pub use aead;

use self::cipher::Cipher;
use ::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use aead::{
    consts::{U0, U12, U16, U24, U32},
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace, Error, NewAead,
};
use core::marker::PhantomData;
use zeroize::Zeroize;

use chacha20::{ChaCha20, XChaCha20};

#[cfg(feature = "reduced-round")]
use chacha20::{ChaCha12, ChaCha8, XChaCha12, XChaCha8};

pub type Key = GenericArray<u8, U32>;

pub type Nonce = GenericArray<u8, U12>;

pub type XNonce = GenericArray<u8, U24>;

pub type Tag = GenericArray<u8, U16>;

pub type ChaCha20Poly1305 = ChaChaPoly1305<ChaCha20, U12>;

pub type XChaCha20Poly1305 = ChaChaPoly1305<XChaCha20, U24>;

#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type ChaCha8Poly1305 = ChaChaPoly1305<ChaCha8, U12>;

#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type ChaCha12Poly1305 = ChaChaPoly1305<ChaCha12, U12>;

#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type XChaCha8Poly1305 = ChaChaPoly1305<XChaCha8, U24>;

#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type XChaCha12Poly1305 = ChaChaPoly1305<XChaCha12, U24>;

pub struct ChaChaPoly1305<C, N: ArrayLength<u8> = U12>
where
    C: KeyIvInit<KeySize = U32, IvSize = N> + StreamCipher + StreamCipherSeek,
{
    key: GenericArray<u8, U32>,
    stream_cipher: PhantomData<C>,
}

impl<C, N> NewAead for ChaChaPoly1305<C, N>
where
    C: KeyIvInit<KeySize = U32, IvSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    type KeySize = U32;

    fn new(key: &Key) -> Self {
        Self {
            key: *key,
            stream_cipher: PhantomData,
        }
    }
}

impl<C, N> AeadCore for ChaChaPoly1305<C, N>
where
    C: KeyIvInit<KeySize = U32, IvSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    type NonceSize = N;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<C, N> AeadInPlace for ChaChaPoly1305<C, N>
where
    C: KeyIvInit<KeySize = U32, IvSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::new(C::new(&self.key, nonce)).encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::new(C::new(&self.key, nonce)).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

impl<C, N> Clone for ChaChaPoly1305<C, N>
where
    C: KeyIvInit<KeySize = U32, IvSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            stream_cipher: PhantomData,
        }
    }
}

impl<C, N> Drop for ChaChaPoly1305<C, N>
where
    C: KeyIvInit<KeySize = U32, IvSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}
