use core::fmt::Debug;

use curve25519::constants;
use curve25519::digest::generic_array::typenum::U64;
use curve25519::digest::Digest;
use curve25519::edwards::CompressedEdwardsY;
use curve25519::scalar::Scalar;

#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};

use sha2::Sha512;

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use serde_bytes::{ByteBuf as SerdeByteBuf, Bytes as SerdeBytes};

use zeroize::Zeroize;

use crate::constants::*;
use crate::errors::*;
use crate::public::*;
use crate::signature::*;

pub struct SecretKey(pub(crate) [u8; SECRET_KEY_LENGTH]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SecretKey: {:?}", &self.0[..])
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl SecretKey {
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0
    }

    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, SignatureError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(InternalError::BytesLengthError {
                name: "SecretKey",
                length: SECRET_KEY_LENGTH,
            }
            .into());
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(SecretKey(bits))
    }

    #[cfg(feature = "rand")]
    pub fn generate<T>(csprng: &mut T) -> SecretKey
    where
        T: CryptoRng + RngCore,
    {
        let mut sk: SecretKey = SecretKey([0u8; 32]);

        csprng.fill_bytes(&mut sk.0);

        sk
    }
}

#[cfg(feature = "serde")]
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(self.as_bytes()).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        SecretKey::from_bytes(bytes.as_ref()).map_err(SerdeError::custom)
    }
}

pub struct ExpandedSecretKey {
    pub(crate) key: Scalar,
    pub(crate) nonce: [u8; 32],
}

impl Drop for ExpandedSecretKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize()
    }
}

impl<'a> From<&'a SecretKey> for ExpandedSecretKey {
    fn from(secret_key: &'a SecretKey) -> ExpandedSecretKey {
        let mut h: Sha512 = Sha512::default();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        h.update(secret_key.as_bytes());
        hash.copy_from_slice(h.finalize().as_slice());

        lower.copy_from_slice(&hash[00..32]);
        upper.copy_from_slice(&hash[32..64]);

        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        ExpandedSecretKey {
            key: Scalar::from_bits(lower),
            nonce: upper,
        }
    }
}

impl ExpandedSecretKey {
    #[inline]
    pub fn to_bytes(&self) -> [u8; EXPANDED_SECRET_KEY_LENGTH] {
        let mut bytes: [u8; 64] = [0u8; 64];

        bytes[..32].copy_from_slice(self.key.as_bytes());
        bytes[32..].copy_from_slice(&self.nonce[..]);
        bytes
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<ExpandedSecretKey, SignatureError> {
        if bytes.len() != EXPANDED_SECRET_KEY_LENGTH {
            return Err(InternalError::BytesLengthError {
                name: "ExpandedSecretKey",
                length: EXPANDED_SECRET_KEY_LENGTH,
            }
            .into());
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[00..32]);
        upper.copy_from_slice(&bytes[32..64]);

        Ok(ExpandedSecretKey {
            key: Scalar::from_bits(lower),
            nonce: upper,
        })
    }

    #[allow(non_snake_case)]
    pub fn sign(&self, message: &[u8], public_key: &PublicKey) -> ed25519::Signature {
        let mut h: Sha512 = Sha512::new();
        let R: CompressedEdwardsY;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        h.update(&self.nonce);
        h.update(&message);

        r = Scalar::from_hash(h);
        R = (&r * &constants::ED25519_BASEPOINT_TABLE).compress();

        h = Sha512::new();
        h.update(R.as_bytes());
        h.update(public_key.as_bytes());
        h.update(&message);

        k = Scalar::from_hash(h);
        s = &(&k * &self.key) + &r;

        InternalSignature { R, s }.into()
    }

    #[allow(non_snake_case)]
    pub fn sign_prehashed<'a, D>(
        &self,
        prehashed_message: D,
        public_key: &PublicKey,
        context: Option<&'a [u8]>,
    ) -> Result<ed25519::Signature, SignatureError>
    where
        D: Digest<OutputSize = U64>,
    {
        let mut h: Sha512;
        let mut prehash: [u8; 64] = [0u8; 64];
        let R: CompressedEdwardsY;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        let ctx: &[u8] = context.unwrap_or(b"");

        if ctx.len() > 255 {
            return Err(SignatureError::from(
                InternalError::PrehashedContextLengthError,
            ));
        }

        let ctx_len: u8 = ctx.len() as u8;

        prehash.copy_from_slice(prehashed_message.finalize().as_slice());

        h = Sha512::new()
            .chain(b"SigEd25519 no Ed25519 collisions")
            .chain(&[1])
            .chain(&[ctx_len])
            .chain(ctx)
            .chain(&self.nonce)
            .chain(&prehash[..]);

        r = Scalar::from_hash(h);
        R = (&r * &constants::ED25519_BASEPOINT_TABLE).compress();

        h = Sha512::new()
            .chain(b"SigEd25519 no Ed25519 collisions")
            .chain(&[1])
            .chain(&[ctx_len])
            .chain(ctx)
            .chain(R.as_bytes())
            .chain(public_key.as_bytes())
            .chain(&prehash[..]);

        k = Scalar::from_hash(h);
        s = &(&k * &self.key) + &r;

        Ok(InternalSignature { R, s }.into())
    }
}

#[cfg(feature = "serde")]
impl Serialize for ExpandedSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = &self.to_bytes()[..];
        SerdeBytes::new(bytes).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for ExpandedSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        ExpandedSecretKey::from_bytes(bytes.as_ref()).map_err(SerdeError::custom)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn secret_key_zeroize_on_drop() {
        let secret_ptr: *const u8;

        {
            let secret = SecretKey::from_bytes(&[0x15u8; 32][..]).unwrap();

            secret_ptr = secret.0.as_ptr();
        }

        let memory: &[u8] = unsafe { ::std::slice::from_raw_parts(secret_ptr, 32) };

        assert!(!memory.contains(&0x15));
    }
}
