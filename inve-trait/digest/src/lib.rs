#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub use crypto_common::rand_core;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

#[cfg(feature = "core-api")]
#[cfg_attr(docsrs, doc(cfg(feature = "core-api")))]
pub mod core_api;
mod digest;
#[cfg(feature = "mac")]
mod mac;

#[cfg(feature = "core-api")]
#[cfg_attr(docsrs, doc(cfg(feature = "core-api")))]
pub use block_buffer;
pub use crypto_common;

pub use crate::digest::{Digest, DynDigest, HashMarker};
pub use crypto_common::{generic_array, typenum, typenum::consts, Output, OutputSizeUser, Reset};
#[cfg(feature = "mac")]
pub use crypto_common::{InnerInit, InvalidLength, Key, KeyInit};
#[cfg(feature = "mac")]
pub use mac::{CtOutput, Mac, MacError, MacMarker};

use core::fmt;

pub trait Update {
    fn update(&mut self, data: &[u8]);

    #[must_use]
    fn chain(mut self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        self.update(data.as_ref());
        self
    }
}

pub trait FixedOutput: Update + OutputSizeUser + Sized {
    fn finalize_into(self, out: &mut Output<Self>);

    #[inline]
    fn finalize_fixed(self) -> Output<Self> {
        let mut out = Default::default();
        self.finalize_into(&mut out);
        out
    }
}

pub trait FixedOutputReset: FixedOutput + Reset {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>);

    #[inline]
    fn finalize_fixed_reset(&mut self) -> Output<Self> {
        let mut out = Default::default();
        self.finalize_into_reset(&mut out);
        out
    }
}

pub trait XofReader {
    fn read(&mut self, buffer: &mut [u8]);

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn read_boxed(&mut self, n: usize) -> Box<[u8]> {
        let mut buf = vec![0u8; n].into_boxed_slice();
        self.read(&mut buf);
        buf
    }
}

pub trait ExtendableOutput: Sized + Update {
    type Reader: XofReader;

    fn finalize_xof(self) -> Self::Reader;

    fn finalize_xof_into(self, out: &mut [u8]) {
        self.finalize_xof().read(out);
    }

    fn digest_xof(input: impl AsRef<[u8]>, output: &mut [u8])
    where
        Self: Default,
    {
        let mut hasher = Self::default();
        hasher.update(input.as_ref());
        hasher.finalize_xof().read(output);
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_boxed(self, output_size: usize) -> Box<[u8]> {
        let mut buf = vec![0u8; output_size].into_boxed_slice();
        self.finalize_xof().read(&mut buf);
        buf
    }
}

pub trait ExtendableOutputReset: ExtendableOutput + Reset {
    fn finalize_xof_reset(&mut self) -> Self::Reader;

    fn finalize_xof_reset_into(&mut self, out: &mut [u8]) {
        self.finalize_xof_reset().read(out);
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_boxed_reset(&mut self, output_size: usize) -> Box<[u8]> {
        let mut buf = vec![0u8; output_size].into_boxed_slice();
        self.finalize_xof_reset().read(&mut buf);
        buf
    }
}

pub trait VariableOutput: Sized + Update {
    const MAX_OUTPUT_SIZE: usize;

    fn new(output_size: usize) -> Result<Self, InvalidOutputSize>;

    fn output_size(&self) -> usize;

    fn finalize_variable(self, out: &mut [u8]) -> Result<(), InvalidBufferSize>;

    fn digest_variable(
        input: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<(), InvalidOutputSize> {
        let mut hasher = Self::new(output.len())?;
        hasher.update(input.as_ref());
        hasher
            .finalize_variable(output)
            .map_err(|_| InvalidOutputSize)
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_boxed(self) -> Box<[u8]> {
        let n = self.output_size();
        let mut buf = vec![0u8; n].into_boxed_slice();
        self.finalize_variable(&mut buf)
            .expect("buf length is equal to output_size");
        buf
    }
}

pub trait VariableOutputReset: VariableOutput + Reset {
    fn finalize_variable_reset(&mut self, out: &mut [u8]) -> Result<(), InvalidBufferSize>;

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_boxed_reset(&mut self) -> Box<[u8]> {
        let n = self.output_size();
        let mut buf = vec![0u8; n].into_boxed_slice();
        self.finalize_variable_reset(&mut buf)
            .expect("buf length is equal to output_size");
        buf
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InvalidOutputSize;

impl fmt::Display for InvalidOutputSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid output size")
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for InvalidOutputSize {}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidBufferSize;

impl fmt::Display for InvalidBufferSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid buffer length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidBufferSize {}
