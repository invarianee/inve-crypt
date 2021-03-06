use crate::{FixedOutput, FixedOutputReset, Update};
use crypto_common::{InvalidLength, Key, KeyInit, Output, OutputSizeUser, Reset};

#[cfg(feature = "rand_core")]
use crate::rand_core::{CryptoRng, RngCore};
use core::fmt;
use crypto_common::typenum::Unsigned;
use subtle::{Choice, ConstantTimeEq};

#[cfg_attr(docsrs, doc(cfg(feature = "mac")))]
pub trait MacMarker {}

#[cfg_attr(docsrs, doc(cfg(feature = "mac")))]
pub trait Mac: OutputSizeUser + Sized {
    fn new(key: &Key<Self>) -> Self
    where
        Self: KeyInit;

    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    fn generate_key(rng: impl CryptoRng + RngCore) -> Key<Self>
    where
        Self: KeyInit;

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength>
    where
        Self: KeyInit;

    fn update(&mut self, data: &[u8]);

    #[must_use]
    fn chain_update(self, data: impl AsRef<[u8]>) -> Self;

    fn finalize(self) -> CtOutput<Self>;

    fn finalize_reset(&mut self) -> CtOutput<Self>
    where
        Self: FixedOutputReset;

    fn reset(&mut self)
    where
        Self: Reset;

    fn verify(self, tag: &Output<Self>) -> Result<(), MacError>;

    fn verify_slice(self, tag: &[u8]) -> Result<(), MacError>;

    fn verify_truncated_left(self, tag: &[u8]) -> Result<(), MacError>;

    fn verify_truncated_right(self, tag: &[u8]) -> Result<(), MacError>;
}

impl<T: Update + FixedOutput + MacMarker> Mac for T {
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self
    where
        Self: KeyInit,
    {
        KeyInit::new(key)
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength>
    where
        Self: KeyInit,
    {
        KeyInit::new_from_slice(key)
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        Update::update(self, data);
    }

    #[inline]
    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        Update::update(&mut self, data.as_ref());
        self
    }

    #[inline]
    fn finalize(self) -> CtOutput<Self> {
        CtOutput::new(self.finalize_fixed())
    }

    #[inline(always)]
    fn finalize_reset(&mut self) -> CtOutput<Self>
    where
        Self: FixedOutputReset,
    {
        CtOutput::new(self.finalize_fixed_reset())
    }

    #[inline]
    fn reset(&mut self)
    where
        Self: Reset,
    {
        Reset::reset(self)
    }

    #[inline]
    fn verify(self, tag: &Output<Self>) -> Result<(), MacError> {
        if self.finalize() == tag.into() {
            Ok(())
        } else {
            Err(MacError)
        }
    }

    #[inline]
    fn verify_slice(self, tag: &[u8]) -> Result<(), MacError> {
        let n = tag.len();
        if n != Self::OutputSize::USIZE {
            return Err(MacError);
        }
        let choice = self.finalize_fixed().ct_eq(tag);
        if choice.unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(MacError)
        }
    }

    fn verify_truncated_left(self, tag: &[u8]) -> Result<(), MacError> {
        let n = tag.len();
        if n == 0 || n > Self::OutputSize::USIZE {
            return Err(MacError);
        }
        let choice = self.finalize_fixed()[..n].ct_eq(tag);

        if choice.unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(MacError)
        }
    }

    fn verify_truncated_right(self, tag: &[u8]) -> Result<(), MacError> {
        let n = tag.len();
        if n == 0 || n > Self::OutputSize::USIZE {
            return Err(MacError);
        }
        let m = Self::OutputSize::USIZE - n;
        let choice = self.finalize_fixed()[m..].ct_eq(tag);

        if choice.unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(MacError)
        }
    }

    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key(rng: impl CryptoRng + RngCore) -> Key<Self>
    where
        Self: KeyInit,
    {
        <T as KeyInit>::generate_key(rng)
    }
}

#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "mac")))]
pub struct CtOutput<T: OutputSizeUser> {
    bytes: Output<T>,
}

impl<T: OutputSizeUser> CtOutput<T> {
    #[inline(always)]
    pub fn new(bytes: Output<T>) -> Self {
        Self { bytes }
    }

    #[inline(always)]
    pub fn into_bytes(self) -> Output<T> {
        self.bytes
    }
}

impl<T: OutputSizeUser> From<Output<T>> for CtOutput<T> {
    #[inline(always)]
    fn from(bytes: Output<T>) -> Self {
        Self { bytes }
    }
}

impl<'a, T: OutputSizeUser> From<&'a Output<T>> for CtOutput<T> {
    #[inline(always)]
    fn from(bytes: &'a Output<T>) -> Self {
        bytes.clone().into()
    }
}

impl<T: OutputSizeUser> ConstantTimeEq for CtOutput<T> {
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<T: OutputSizeUser> PartialEq for CtOutput<T> {
    #[inline(always)]
    fn eq(&self, x: &CtOutput<T>) -> bool {
        self.ct_eq(x).unwrap_u8() == 1
    }
}

impl<T: OutputSizeUser> Eq for CtOutput<T> {}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(docsrs, doc(cfg(feature = "mac")))]
pub struct MacError;

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MAC tag mismatch")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MacError {}
