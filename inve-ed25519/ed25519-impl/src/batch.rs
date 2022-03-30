#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use core::convert::TryFrom;
use core::iter::once;

use curve25519::constants;
use curve25519::edwards::EdwardsPoint;
use curve25519::scalar::Scalar;
use curve25519::traits::IsIdentity;
use curve25519::traits::VartimeMultiscalarMul;

pub use curve25519::digest::Digest;

use merlin::Transcript;

#[cfg(all(feature = "batch", not(feature = "batch_deterministic")))]
use rand::thread_rng;
use rand::Rng;
#[cfg(all(not(feature = "batch"), feature = "batch_deterministic"))]
use rand_core;

use sha2::Sha512;

use crate::errors::InternalError;
use crate::errors::SignatureError;
use crate::public::PublicKey;
use crate::signature::InternalSignature;

trait BatchTranscript {
    fn append_scalars(&mut self, scalars: &Vec<Scalar>);
    fn append_message_lengths(&mut self, message_lengths: &Vec<usize>);
}

impl BatchTranscript for Transcript {
    fn append_scalars(&mut self, scalars: &Vec<Scalar>) {
        for (i, scalar) in scalars.iter().enumerate() {
            self.append_u64(b"", i as u64);
            self.append_message(b"hram", scalar.as_bytes());
        }
    }

    fn append_message_lengths(&mut self, message_lengths: &Vec<usize>) {
        for (i, len) in message_lengths.iter().enumerate() {
            self.append_u64(b"", i as u64);
            self.append_u64(b"mlen", *len as u64);
        }
    }
}

#[cfg(all(not(feature = "batch"), feature = "batch_deterministic"))]
struct ZeroRng {}

#[cfg(all(not(feature = "batch"), feature = "batch_deterministic"))]
impl rand_core::RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {}

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(all(not(feature = "batch"), feature = "batch_deterministic"))]
impl rand_core::CryptoRng for ZeroRng {}

#[cfg(all(not(feature = "batch"), feature = "batch_deterministic"))]
fn zero_rng() -> ZeroRng {
    ZeroRng {}
}

#[cfg(all(
    any(feature = "batch", feature = "batch_deterministic"),
    any(feature = "alloc", feature = "std")
))]
#[allow(non_snake_case)]
pub fn verify_batch(
    messages: &[&[u8]],
    signatures: &[ed25519::Signature],
    public_keys: &[PublicKey],
) -> Result<(), SignatureError> {
    if signatures.len() != messages.len()
        || signatures.len() != public_keys.len()
        || public_keys.len() != messages.len()
    {
        return Err(InternalError::ArrayLengthError {
            name_a: "signatures",
            length_a: signatures.len(),
            name_b: "messages",
            length_b: messages.len(),
            name_c: "public_keys",
            length_c: public_keys.len(),
        }
        .into());
    }

    let signatures = signatures
        .iter()
        .map(InternalSignature::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let hrams: Vec<Scalar> = (0..signatures.len())
        .map(|i| {
            let mut h: Sha512 = Sha512::default();
            h.update(signatures[i].R.as_bytes());
            h.update(public_keys[i].as_bytes());
            h.update(&messages[i]);
            Scalar::from_hash(h)
        })
        .collect();

    let message_lengths: Vec<usize> = messages.iter().map(|i| i.len()).collect();
    let scalars: Vec<Scalar> = signatures.iter().map(|i| i.s).collect();

    let mut transcript: Transcript = Transcript::new(b"ed25519 batch verification");

    transcript.append_scalars(&hrams);
    transcript.append_message_lengths(&message_lengths);
    transcript.append_scalars(&scalars);

    #[cfg(all(feature = "batch", not(feature = "batch_deterministic")))]
    let mut prng = transcript.build_rng().finalize(&mut thread_rng());
    #[cfg(all(not(feature = "batch"), feature = "batch_deterministic"))]
    let mut prng = transcript.build_rng().finalize(&mut zero_rng());

    let zs: Vec<Scalar> = signatures
        .iter()
        .map(|_| Scalar::from(prng.gen::<u128>()))
        .collect();

    let B_coefficient: Scalar = signatures
        .iter()
        .map(|sig| sig.s)
        .zip(zs.iter())
        .map(|(s, z)| z * s)
        .sum();

    let zhrams = hrams.iter().zip(zs.iter()).map(|(hram, z)| hram * z);

    let Rs = signatures.iter().map(|sig| sig.R.decompress());
    let As = public_keys.iter().map(|pk| Some(pk.1));
    let B = once(Some(constants::ED25519_BASEPOINT_POINT));

    let id = EdwardsPoint::optional_multiscalar_mul(
        once(-B_coefficient).chain(zs.iter().cloned()).chain(zhrams),
        B.chain(Rs).chain(As),
    )
    .ok_or(InternalError::VerifyError)?;

    if id.is_identity() {
        Ok(())
    } else {
        Err(InternalError::VerifyError.into())
    }
}
