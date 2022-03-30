pub mod recoverable;

#[cfg(feature = "ecdsa")]
mod normalize;
#[cfg(feature = "ecdsa")]
mod sign;
#[cfg(feature = "ecdsa")]
mod verify;

pub use ecdsa_core::signature::{self, Error};

#[cfg(feature = "digest")]
pub use ecdsa_core::signature::digest;

#[cfg(feature = "ecdsa")]
pub use self::{sign::SigningKey, verify::VerifyingKey};

use crate::Secp256k1;

pub type Signature = ecdsa_core::Signature<Secp256k1>;

pub type DerSignature = ecdsa_core::der::Signature<Secp256k1>;

#[cfg(feature = "sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha256")))]
impl ecdsa_core::hazmat::DigestPrimitive for Secp256k1 {
    type Digest = sha2::Sha256;
}

#[cfg(all(test, feature = "ecdsa", feature = "arithmetic"))]
mod tests {
    mod wycheproof {
        use crate::{EncodedPoint, Secp256k1};
        use ecdsa_core::{signature::Verifier, Signature};

        #[test]
        fn wycheproof() {
            use blobby::Blob5Iterator;
            use elliptic_curve::bigint::Encoding as _;

            fn element_from_padded_slice<C: elliptic_curve::Curve>(
                data: &[u8],
            ) -> elliptic_curve::FieldBytes<C> {
                let point_len = C::UInt::BYTE_SIZE;
                if data.len() >= point_len {
                    let offset = data.len() - point_len;
                    for v in data.iter().take(offset) {
                        assert_eq!(*v, 0, "EcdsaVerifier: point too large");
                    }
                    elliptic_curve::FieldBytes::<C>::clone_from_slice(&data[offset..])
                } else {
                    let iter = core::iter::repeat(0)
                        .take(point_len - data.len())
                        .chain(data.iter().cloned());
                    elliptic_curve::FieldBytes::<C>::from_exact_iter(iter).unwrap()
                }
            }

            fn run_test(
                wx: &[u8],
                wy: &[u8],
                msg: &[u8],
                sig: &[u8],
                pass: bool,
            ) -> Option<&'static str> {
                let x = element_from_padded_slice::<Secp256k1>(wx);
                let y = element_from_padded_slice::<Secp256k1>(wy);
                let q_encoded =
                    EncodedPoint::from_affine_coordinates(&x, &y, /* compress= */ false);
                let verifying_key =
                    ecdsa_core::VerifyingKey::from_encoded_point(&q_encoded).unwrap();

                let sig = match Signature::<Secp256k1>::from_der(sig) {
                    Ok(s) => s.normalize_s().unwrap_or(s),
                    Err(_) if !pass => return None,
                    Err(_) => return Some("failed to parse signature ASN.1"),
                };

                match verifying_key.verify(msg, &sig) {
                    Ok(_) if pass => None,
                    Ok(_) => Some("signature verify unexpectedly succeeded"),
                    Err(_) if !pass => None,
                    Err(_) => Some("signature verify failed"),
                }
            }

            let data = include_bytes!(concat!("test_vectors/data/", "wycheproof", ".blb"));

            for (i, row) in Blob5Iterator::new(data).unwrap().enumerate() {
                let [wx, wy, msg, sig, status] = row.unwrap();
                let pass = match status[0] {
                    0 => false,
                    1 => true,
                    _ => panic!("invalid value for pass flag"),
                };
                if let Some(desc) = run_test(wx, wy, msg, sig, pass) {
                    panic!(
                        "\n\
                                 Failed test №{}: {}\n\
                                 wx:\t{:?}\n\
                                 wy:\t{:?}\n\
                                 msg:\t{:?}\n\
                                 sig:\t{:?}\n\
                                 pass:\t{}\n",
                        i, desc, wx, wy, msg, sig, pass,
                    );
                }
            }
        }
    }
}
