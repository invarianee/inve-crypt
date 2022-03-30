use core::convert::TryFrom;
use core::fmt::Debug;

use curve25519::edwards::CompressedEdwardsY;
use curve25519::scalar::Scalar;
use ed25519::signature::Signature as _;

use crate::constants::*;
use crate::errors::*;

#[allow(non_snake_case)]
#[derive(Copy, Eq, PartialEq)]
pub(crate) struct InternalSignature {
    pub(crate) R: CompressedEdwardsY,

    pub(crate) s: Scalar,
}

impl Clone for InternalSignature {
    fn clone(&self) -> Self {
        *self
    }
}

impl Debug for InternalSignature {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "Signature( R: {:?}, s: {:?} )", &self.R, &self.s)
    }
}

#[cfg(feature = "legacy_compatibility")]
#[inline(always)]
fn check_scalar(bytes: [u8; 32]) -> Result<Scalar, SignatureError> {
    if bytes[31] & 224 != 0 {
        return Err(InternalError::ScalarFormatError.into());
    }

    Ok(Scalar::from_bits(bytes))
}

#[cfg(not(feature = "legacy_compatibility"))]
#[inline(always)]
fn check_scalar(bytes: [u8; 32]) -> Result<Scalar, SignatureError> {
    if bytes[31] & 240 == 0 {
        return Ok(Scalar::from_bits(bytes));
    }

    match Scalar::from_canonical_bytes(bytes) {
        None => return Err(InternalError::ScalarFormatError.into()),
        Some(x) => return Ok(x),
    };
}

impl InternalSignature {
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];

        signature_bytes[..32].copy_from_slice(&self.R.as_bytes()[..]);
        signature_bytes[32..].copy_from_slice(&self.s.as_bytes()[..]);
        signature_bytes
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<InternalSignature, SignatureError> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(InternalError::BytesLengthError {
                name: "Signature",
                length: SIGNATURE_LENGTH,
            }
            .into());
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[..32]);
        upper.copy_from_slice(&bytes[32..]);

        let s: Scalar;

        match check_scalar(upper) {
            Ok(x) => s = x,
            Err(x) => return Err(x),
        }

        Ok(InternalSignature {
            R: CompressedEdwardsY(lower),
            s: s,
        })
    }
}

impl TryFrom<&ed25519::Signature> for InternalSignature {
    type Error = SignatureError;

    fn try_from(sig: &ed25519::Signature) -> Result<InternalSignature, SignatureError> {
        InternalSignature::from_bytes(sig.as_bytes())
    }
}

impl From<InternalSignature> for ed25519::Signature {
    fn from(sig: InternalSignature) -> ed25519::Signature {
        ed25519::Signature::from_bytes(&sig.to_bytes()).unwrap()
    }
}
