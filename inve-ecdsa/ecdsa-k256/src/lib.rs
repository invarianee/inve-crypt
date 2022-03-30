#[cfg(feature = "arithmetic")]
mod arithmetic;

#[cfg(feature = "ecdh")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdh")))]
pub mod ecdh;

#[cfg(feature = "ecdsa-core")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa-core")))]
pub mod ecdsa;

#[cfg(any(feature = "test-vectors", test))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-vectors")))]
pub mod test_vectors;

pub use elliptic_curve::{self, bigint::U256};

#[cfg(feature = "arithmetic")]
pub use arithmetic::{affine::AffinePoint, projective::ProjectivePoint, scalar::Scalar};

#[cfg(feature = "expose-field")]
pub use arithmetic::FieldElement;

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
pub use elliptic_curve::pkcs8;

use elliptic_curve::{consts::U33, generic_array::GenericArray};

const ORDER: U256 =
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Secp256k1;

impl elliptic_curve::Curve for Secp256k1 {
    type UInt = U256;

    const ORDER: U256 = ORDER;
}

impl elliptic_curve::PrimeCurve for Secp256k1 {}

impl elliptic_curve::PointCompression for Secp256k1 {
    const COMPRESS_POINTS: bool = true;
}

#[cfg(feature = "jwk")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
impl elliptic_curve::JwkParameters for Secp256k1 {
    const CRV: &'static str = "secp256k1";
}

#[cfg(feature = "pkcs8")]
impl elliptic_curve::AlgorithmParameters for Secp256k1 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new("1.3.132.0.10");
}

pub type CompressedPoint = GenericArray<u8, U33>;

pub type FieldBytes = elliptic_curve::FieldBytes<Secp256k1>;

pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<Secp256k1>;

#[cfg(feature = "arithmetic")]
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<Secp256k1>;

#[cfg(feature = "arithmetic")]
pub type PublicKey = elliptic_curve::PublicKey<Secp256k1>;

pub type SecretKey = elliptic_curve::SecretKey<Secp256k1>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for Secp256k1 {}

#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
pub type ScalarBits = elliptic_curve::ScalarBits<Secp256k1>;
