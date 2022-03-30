use core::convert::TryFrom;
use core::fmt::Debug;

use curve25519::constants;
use curve25519::digest::generic_array::typenum::U64;
use curve25519::digest::Digest;
use curve25519::edwards::CompressedEdwardsY;
use curve25519::edwards::EdwardsPoint;
use curve25519::scalar::Scalar;

use ed25519::signature::Verifier;

pub use sha2::Sha512;

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use serde_bytes::{ByteBuf as SerdeByteBuf, Bytes as SerdeBytes};

use crate::constants::*;
use crate::errors::*;
use crate::secret::*;
use crate::signature::*;

#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct PublicKey(pub(crate) CompressedEdwardsY, pub(crate) EdwardsPoint);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKey({:?}), {:?})", self.0, self.1)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> PublicKey {
        let mut h: Sha512 = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut digest: [u8; 32] = [0u8; 32];

        h.update(secret_key.as_bytes());
        hash.copy_from_slice(h.finalize().as_slice());

        digest.copy_from_slice(&hash[..32]);

        PublicKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(&mut digest)
    }
}

impl<'a> From<&'a ExpandedSecretKey> for PublicKey {
    fn from(expanded_secret_key: &ExpandedSecretKey) -> PublicKey {
        let mut bits: [u8; 32] = expanded_secret_key.key.to_bytes();

        PublicKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(&mut bits)
    }
}

impl PublicKey {
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PUBLIC_KEY_LENGTH] {
        &(self.0).0
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(InternalError::BytesLengthError {
                name: "PublicKey",
                length: PUBLIC_KEY_LENGTH,
            }
            .into());
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        let compressed = CompressedEdwardsY(bits);
        let point = compressed
            .decompress()
            .ok_or(InternalError::PointDecompressionError)?;

        Ok(PublicKey(compressed, point))
    }

    fn mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(
        bits: &mut [u8; 32],
    ) -> PublicKey {
        bits[0] &= 248;
        bits[31] &= 127;
        bits[31] |= 64;

        let point = &Scalar::from_bits(*bits) * &constants::ED25519_BASEPOINT_TABLE;
        let compressed = point.compress();

        PublicKey(compressed, point)
    }

    #[allow(non_snake_case)]
    pub fn verify_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
        signature: &ed25519::Signature,
    ) -> Result<(), SignatureError>
    where
        D: Digest<OutputSize = U64>,
    {
        let signature = InternalSignature::try_from(signature)?;

        let mut h: Sha512 = Sha512::default();
        let R: EdwardsPoint;
        let k: Scalar;

        let ctx: &[u8] = context.unwrap_or(b"");
        debug_assert!(
            ctx.len() <= 255,
            "The context must not be longer than 255 octets."
        );

        let minus_A: EdwardsPoint = -self.1;

        h.update(b"SigEd25519 no Ed25519 collisions");
        h.update(&[1]);
        h.update(&[ctx.len() as u8]);
        h.update(ctx);
        h.update(signature.R.as_bytes());
        h.update(self.as_bytes());
        h.update(prehashed_message.finalize().as_slice());

        k = Scalar::from_hash(h);
        R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &signature.s);

        if R.compress() == signature.R {
            Ok(())
        } else {
            Err(InternalError::VerifyError.into())
        }
    }

    #[allow(non_snake_case)]
    pub fn verify_strict(
        &self,
        message: &[u8],
        signature: &ed25519::Signature,
    ) -> Result<(), SignatureError> {
        let signature = InternalSignature::try_from(signature)?;

        let mut h: Sha512 = Sha512::new();
        let R: EdwardsPoint;
        let k: Scalar;
        let minus_A: EdwardsPoint = -self.1;
        let signature_R: EdwardsPoint;

        match signature.R.decompress() {
            None => return Err(InternalError::VerifyError.into()),
            Some(x) => signature_R = x,
        }

        if signature_R.is_small_order() || self.1.is_small_order() {
            return Err(InternalError::VerifyError.into());
        }

        h.update(signature.R.as_bytes());
        h.update(self.as_bytes());
        h.update(&message);

        k = Scalar::from_hash(h);
        R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &signature.s);

        if R == signature_R {
            Ok(())
        } else {
            Err(InternalError::VerifyError.into())
        }
    }
}

impl Verifier<ed25519::Signature> for PublicKey {
    #[allow(non_snake_case)]
    fn verify(&self, message: &[u8], signature: &ed25519::Signature) -> Result<(), SignatureError> {
        let signature = InternalSignature::try_from(signature)?;

        let mut h: Sha512 = Sha512::new();
        let R: EdwardsPoint;
        let k: Scalar;
        let minus_A: EdwardsPoint = -self.1;

        h.update(signature.R.as_bytes());
        h.update(self.as_bytes());
        h.update(&message);

        k = Scalar::from_hash(h);
        R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &signature.s);

        if R.compress() == signature.R {
            Ok(())
        } else {
            Err(InternalError::VerifyError.into())
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(self.as_bytes()).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        PublicKey::from_bytes(bytes.as_ref()).map_err(SerdeError::custom)
    }
}
