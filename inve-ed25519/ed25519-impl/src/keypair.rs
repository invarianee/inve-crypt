#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use serde_bytes::{ByteBuf as SerdeByteBuf, Bytes as SerdeBytes};

pub use sha2::Sha512;

use curve25519::digest::generic_array::typenum::U64;
pub use curve25519::digest::Digest;

use ed25519::signature::{Signer, Verifier};

use crate::constants::*;
use crate::errors::*;
use crate::public::*;
use crate::secret::*;

#[derive(Debug)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    pub fn to_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        let mut bytes: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        bytes[..SECRET_KEY_LENGTH].copy_from_slice(self.secret.as_bytes());
        bytes[SECRET_KEY_LENGTH..].copy_from_slice(self.public.as_bytes());
        bytes
    }

    pub fn from_bytes<'a>(bytes: &'a [u8]) -> Result<Keypair, SignatureError> {
        if bytes.len() != KEYPAIR_LENGTH {
            return Err(InternalError::BytesLengthError {
                name: "Keypair",
                length: KEYPAIR_LENGTH,
            }
            .into());
        }
        let secret = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH])?;
        let public = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..])?;

        Ok(Keypair {
            secret: secret,
            public: public,
        })
    }

    #[cfg(feature = "rand")]
    pub fn generate<R>(csprng: &mut R) -> Keypair
    where
        R: CryptoRng + RngCore,
    {
        let sk: SecretKey = SecretKey::generate(csprng);
        let pk: PublicKey = (&sk).into();

        Keypair {
            public: pk,
            secret: sk,
        }
    }

    pub fn sign_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
    ) -> Result<ed25519::Signature, SignatureError>
    where
        D: Digest<OutputSize = U64>,
    {
        let expanded: ExpandedSecretKey = (&self.secret).into();

        expanded
            .sign_prehashed(prehashed_message, &self.public, context)
            .into()
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &ed25519::Signature,
    ) -> Result<(), SignatureError> {
        self.public.verify(message, signature)
    }

    pub fn verify_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
        signature: &ed25519::Signature,
    ) -> Result<(), SignatureError>
    where
        D: Digest<OutputSize = U64>,
    {
        self.public
            .verify_prehashed(prehashed_message, context, signature)
    }

    #[allow(non_snake_case)]
    pub fn verify_strict(
        &self,
        message: &[u8],
        signature: &ed25519::Signature,
    ) -> Result<(), SignatureError> {
        self.public.verify_strict(message, signature)
    }
}

impl Signer<ed25519::Signature> for Keypair {
    fn try_sign(&self, message: &[u8]) -> Result<ed25519::Signature, SignatureError> {
        let expanded: ExpandedSecretKey = (&self.secret).into();
        Ok(expanded.sign(&message, &self.public).into())
    }
}

impl Verifier<ed25519::Signature> for Keypair {
    fn verify(&self, message: &[u8], signature: &ed25519::Signature) -> Result<(), SignatureError> {
        self.public.verify(message, signature)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Keypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = &self.to_bytes()[..];
        SerdeBytes::new(bytes).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Keypair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        Keypair::from_bytes(bytes.as_ref()).map_err(SerdeError::custom)
    }
}
