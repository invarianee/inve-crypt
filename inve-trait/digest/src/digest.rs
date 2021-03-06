use super::{FixedOutput, FixedOutputReset, InvalidBufferSize, Reset, Update};
use crypto_common::{typenum::Unsigned, Output, OutputSizeUser};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

pub trait HashMarker {}

pub trait Digest: OutputSizeUser {
    fn new() -> Self;

    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self;

    fn update(&mut self, data: impl AsRef<[u8]>);

    #[must_use]
    fn chain_update(self, data: impl AsRef<[u8]>) -> Self;

    fn finalize(self) -> Output<Self>;

    fn finalize_into(self, out: &mut Output<Self>);

    fn finalize_reset(&mut self) -> Output<Self>
    where
        Self: FixedOutputReset;

    fn finalize_into_reset(&mut self, out: &mut Output<Self>)
    where
        Self: FixedOutputReset;

    fn reset(&mut self)
    where
        Self: Reset;

    fn output_size() -> usize;

    fn digest(data: impl AsRef<[u8]>) -> Output<Self>;
}

impl<D: FixedOutput + Default + Update + HashMarker> Digest for D {
    #[inline]
    fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self
    where
        Self: Default + Sized,
    {
        let mut h = Self::default();
        h.update(data.as_ref());
        h
    }

    #[inline]
    fn update(&mut self, data: impl AsRef<[u8]>) {
        Update::update(self, data.as_ref());
    }

    #[inline]
    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        Update::update(&mut self, data.as_ref());
        self
    }

    #[inline]
    fn finalize(self) -> Output<Self> {
        FixedOutput::finalize_fixed(self)
    }

    #[inline]
    fn finalize_into(self, out: &mut Output<Self>) {
        FixedOutput::finalize_into(self, out);
    }

    #[inline]
    fn finalize_reset(&mut self) -> Output<Self>
    where
        Self: FixedOutputReset,
    {
        FixedOutputReset::finalize_fixed_reset(self)
    }

    #[inline]
    fn finalize_into_reset(&mut self, out: &mut Output<Self>)
    where
        Self: FixedOutputReset,
    {
        FixedOutputReset::finalize_into_reset(self, out);
    }

    #[inline]
    fn reset(&mut self)
    where
        Self: Reset,
    {
        Reset::reset(self)
    }

    #[inline]
    fn output_size() -> usize {
        Self::OutputSize::to_usize()
    }

    #[inline]
    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        let mut hasher = Self::default();
        hasher.update(data.as_ref());
        hasher.finalize()
    }
}

pub trait DynDigest {
    fn update(&mut self, data: &[u8]);

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_reset(&mut self) -> Box<[u8]> {
        let mut result = vec![0; self.output_size()];
        self.finalize_into_reset(&mut result).unwrap();
        result.into_boxed_slice()
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[allow(clippy::boxed_local)]
    fn finalize(mut self: Box<Self>) -> Box<[u8]> {
        let mut result = vec![0; self.output_size()];
        self.finalize_into_reset(&mut result).unwrap();
        result.into_boxed_slice()
    }

    fn finalize_into(self, buf: &mut [u8]) -> Result<(), InvalidBufferSize>;

    fn finalize_into_reset(&mut self, out: &mut [u8]) -> Result<(), InvalidBufferSize>;

    fn reset(&mut self);

    fn output_size(&self) -> usize;

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn box_clone(&self) -> Box<dyn DynDigest>;
}

impl<D: Update + FixedOutputReset + Reset + Clone + 'static> DynDigest for D {
    fn update(&mut self, data: &[u8]) {
        Update::update(self, data);
    }

    #[cfg(feature = "alloc")]
    fn finalize_reset(&mut self) -> Box<[u8]> {
        FixedOutputReset::finalize_fixed_reset(self)
            .to_vec()
            .into_boxed_slice()
    }

    #[cfg(feature = "alloc")]
    fn finalize(self: Box<Self>) -> Box<[u8]> {
        FixedOutput::finalize_fixed(*self)
            .to_vec()
            .into_boxed_slice()
    }

    fn finalize_into(self, buf: &mut [u8]) -> Result<(), InvalidBufferSize> {
        if buf.len() == self.output_size() {
            FixedOutput::finalize_into(self, Output::<Self>::from_mut_slice(buf));
            Ok(())
        } else {
            Err(InvalidBufferSize)
        }
    }

    fn finalize_into_reset(&mut self, buf: &mut [u8]) -> Result<(), InvalidBufferSize> {
        if buf.len() == self.output_size() {
            FixedOutputReset::finalize_into_reset(self, Output::<Self>::from_mut_slice(buf));
            Ok(())
        } else {
            Err(InvalidBufferSize)
        }
    }

    fn reset(&mut self) {
        Reset::reset(self);
    }

    fn output_size(&self) -> usize {
        <Self as OutputSizeUser>::OutputSize::to_usize()
    }

    #[cfg(feature = "alloc")]
    fn box_clone(&self) -> Box<dyn DynDigest> {
        Box::new(self.clone())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Clone for Box<dyn DynDigest> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
