#![allow(non_snake_case)]

use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum InternalError {
    PointDecompressionError,
    ScalarFormatError,
    BytesLengthError {
        name: &'static str,
        length: usize,
    },
    VerifyError,
    ArrayLengthError {
        name_a: &'static str,
        length_a: usize,
        name_b: &'static str,
        length_b: usize,
        name_c: &'static str,
        length_c: usize,
    },
    PrehashedContextLengthError,
}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            InternalError::PointDecompressionError => write!(f, "Cannot decompress Edwards point"),
            InternalError::ScalarFormatError => write!(f, "Cannot use scalar with high-bit set"),
            InternalError::BytesLengthError { name: n, length: l } => {
                write!(f, "{} must be {} bytes in length", n, l)
            }
            InternalError::VerifyError => write!(f, "Verification equation was not satisfied"),
            InternalError::ArrayLengthError {
                name_a: na,
                length_a: la,
                name_b: nb,
                length_b: lb,
                name_c: nc,
                length_c: lc,
            } => write!(
                f,
                "Arrays must be the same length: {} has length {},
                              {} has length {}, {} has length {}.",
                na, la, nb, lb, nc, lc
            ),
            InternalError::PrehashedContextLengthError => write!(
                f,
                "An ed25519ph signature can only take up to 255 octets of context"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl Error for InternalError {}

pub type SignatureError = ed25519::signature::Error;

impl From<InternalError> for SignatureError {
    #[cfg(not(feature = "std"))]
    fn from(_err: InternalError) -> SignatureError {
        SignatureError::new()
    }

    #[cfg(feature = "std")]
    fn from(err: InternalError) -> SignatureError {
        SignatureError::from_source(err)
    }
}
