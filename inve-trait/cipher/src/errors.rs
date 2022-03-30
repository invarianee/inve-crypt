use core::fmt;

#[derive(Copy, Clone, Debug)]
pub struct StreamCipherError;

impl fmt::Display for StreamCipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Loop Error")
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for StreamCipherError {}

#[derive(Copy, Clone, Debug)]
pub struct OverflowError;

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Overflow Error")
    }
}

impl From<OverflowError> for StreamCipherError {
    fn from(_: OverflowError) -> StreamCipherError {
        StreamCipherError
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for OverflowError {}
