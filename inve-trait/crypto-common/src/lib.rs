#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "rand_core")]
pub use rand_core;

pub use generic_array;
pub use generic_array::typenum;

use core::fmt;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

pub type Block<B> = GenericArray<u8, <B as BlockSizeUser>::BlockSize>;
pub type Output<T> = GenericArray<u8, <T as OutputSizeUser>::OutputSize>;
pub type Key<B> = GenericArray<u8, <B as KeySizeUser>::KeySize>;
pub type Iv<B> = GenericArray<u8, <B as IvSizeUser>::IvSize>;

pub trait BlockSizeUser {
    type BlockSize: ArrayLength<u8> + 'static;

    fn block_size() -> usize {
        Self::BlockSize::USIZE
    }
}

impl<T: BlockSizeUser> BlockSizeUser for &T {
    type BlockSize = T::BlockSize;
}

impl<T: BlockSizeUser> BlockSizeUser for &mut T {
    type BlockSize = T::BlockSize;
}

pub trait OutputSizeUser {
    type OutputSize: ArrayLength<u8> + 'static;

    fn output_size() -> usize {
        Self::OutputSize::USIZE
    }
}

pub trait KeySizeUser {
    type KeySize: ArrayLength<u8> + 'static;

    fn key_size() -> usize {
        Self::KeySize::USIZE
    }
}

pub trait IvSizeUser {
    type IvSize: ArrayLength<u8> + 'static;

    fn iv_size() -> usize {
        Self::IvSize::USIZE
    }
}

pub trait InnerUser {
    type Inner;
}

pub trait Reset {
    fn reset(&mut self);
}

pub trait AlgorithmName {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

pub trait KeyInit: KeySizeUser + Sized {
    fn new(key: &Key<Self>) -> Self;

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() != Self::KeySize::to_usize() {
            Err(InvalidLength)
        } else {
            Ok(Self::new(Key::<Self>::from_slice(key)))
        }
    }

    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> Key<Self> {
        let mut key = Key::<Self>::default();
        rng.fill_bytes(&mut key);
        key
    }
}

pub trait KeyIvInit: KeySizeUser + IvSizeUser + Sized {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self;

    #[inline]
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        let key_len = Self::KeySize::USIZE;
        let iv_len = Self::IvSize::USIZE;
        if key.len() != key_len || iv.len() != iv_len {
            Err(InvalidLength)
        } else {
            Ok(Self::new(
                Key::<Self>::from_slice(key),
                Iv::<Self>::from_slice(iv),
            ))
        }
    }

    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> Key<Self> {
        let mut key = Key::<Self>::default();
        rng.fill_bytes(&mut key);
        key
    }

    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_iv(mut rng: impl CryptoRng + RngCore) -> Iv<Self> {
        let mut iv = Iv::<Self>::default();
        rng.fill_bytes(&mut iv);
        iv
    }

    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key_iv(mut rng: impl CryptoRng + RngCore) -> (Key<Self>, Iv<Self>) {
        (Self::generate_key(&mut rng), Self::generate_iv(&mut rng))
    }
}

pub trait InnerInit: InnerUser + Sized {
    fn inner_init(inner: Self::Inner) -> Self;
}

pub trait InnerIvInit: InnerUser + IvSizeUser + Sized {
    fn inner_iv_init(inner: Self::Inner, iv: &Iv<Self>) -> Self;

    fn inner_iv_slice_init(inner: Self::Inner, iv: &[u8]) -> Result<Self, InvalidLength> {
        if iv.len() != Self::IvSize::to_usize() {
            Err(InvalidLength)
        } else {
            Ok(Self::inner_iv_init(inner, Iv::<Self>::from_slice(iv)))
        }
    }

    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_iv(mut rng: impl CryptoRng + RngCore) -> Iv<Self> {
        let mut iv = Iv::<Self>::default();
        rng.fill_bytes(&mut iv);
        iv
    }
}

impl<T> KeySizeUser for T
where
    T: InnerUser,
    T::Inner: KeySizeUser,
{
    type KeySize = <T::Inner as KeySizeUser>::KeySize;
}

impl<T> KeyIvInit for T
where
    T: InnerIvInit,
    T::Inner: KeyInit,
{
    #[inline]
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self::inner_iv_init(T::Inner::new(key), iv)
    }

    #[inline]
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        T::Inner::new_from_slice(key).and_then(|i| T::inner_iv_slice_init(i, iv))
    }
}

impl<T> KeyInit for T
where
    T: InnerInit,
    T::Inner: KeyInit,
{
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self::inner_init(T::Inner::new(key))
    }

    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        T::Inner::new_from_slice(key)
            .map_err(|_| InvalidLength)
            .map(Self::inner_init)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Invalid Length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLength {}
