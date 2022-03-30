pub use ecdsa_core::signature::{self, Error};

use super::NistP256;

#[cfg(feature = "ecdsa")]
use {
    crate::{AffinePoint, Scalar},
    ecdsa_core::hazmat::{SignPrimitive, VerifyPrimitive},
};

pub type Signature = ecdsa_core::Signature<NistP256>;

pub type DerSignature = ecdsa_core::der::Signature<NistP256>;

#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub type SigningKey = ecdsa_core::SigningKey<NistP256>;

#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub type VerifyingKey = ecdsa_core::VerifyingKey<NistP256>;

#[cfg(feature = "sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha256")))]
impl ecdsa_core::hazmat::DigestPrimitive for NistP256 {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "ecdsa")]
impl SignPrimitive<NistP256> for Scalar {}

#[cfg(feature = "ecdsa")]
impl VerifyPrimitive<NistP256> for AffinePoint {}

#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    use crate::{
        ecdsa::{signature::Signer, SigningKey},
        test_vectors::ecdsa::ECDSA_TEST_VECTORS,
        BlindedScalar, Scalar,
    };
    use ecdsa_core::hazmat::SignPrimitive;
    use elliptic_curve::{generic_array::GenericArray, group::ff::PrimeField, rand_core::OsRng};
    use hex_literal::hex;

    #[test]
    fn rfc6979() {
        let x = &hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let signer = SigningKey::from_bytes(x).unwrap();
        let signature = signer.sign(b"sample");
        assert_eq!(
            signature.as_ref(),
            &hex!(
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716
                     f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
            )[..]
        );
    }

    #[test]
    fn scalar_blinding() {
        let vector = &ECDSA_TEST_VECTORS[0];
        let d = Scalar::from_repr(GenericArray::clone_from_slice(vector.d)).unwrap();
        let k = Scalar::from_repr(GenericArray::clone_from_slice(vector.k)).unwrap();
        let k_blinded = BlindedScalar::new(k, &mut OsRng);
        let z = Scalar::from_repr(GenericArray::clone_from_slice(vector.m)).unwrap();
        let sig = d.try_sign_prehashed(k_blinded, z).unwrap().0;

        assert_eq!(vector.r, sig.r().to_bytes().as_slice());
        assert_eq!(vector.s, sig.s().to_bytes().as_slice());
    }

    mod sign {
        use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, NistP256};
        ecdsa_core::new_signing_test!(NistP256, ECDSA_TEST_VECTORS);
    }

    mod verify {
        use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, NistP256};
        ecdsa_core::new_verification_test!(NistP256, ECDSA_TEST_VECTORS);
    }

    mod wycheproof {
        use crate::NistP256;
        ecdsa_core::new_wycheproof_test!(wycheproof, "wycheproof", NistP256);
    }
}
