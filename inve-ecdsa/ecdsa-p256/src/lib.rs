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
pub use arithmetic::{
    affine::AffinePoint,
    projective::ProjectivePoint,
    scalar::{blinded::BlindedScalar, Scalar},
};

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
pub use elliptic_curve::pkcs8;

use elliptic_curve::{consts::U33, generic_array::GenericArray};

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct NistP256;

impl elliptic_curve::Curve for NistP256 {
    type UInt = U256;

    const ORDER: U256 =
        U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
}

impl elliptic_curve::PrimeCurve for NistP256 {}

impl elliptic_curve::PointCompression for NistP256 {
    const COMPRESS_POINTS: bool = false;
}

impl elliptic_curve::PointCompaction for NistP256 {
    const COMPACT_POINTS: bool = false;
}

#[cfg(feature = "jwk")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
impl elliptic_curve::JwkParameters for NistP256 {
    const CRV: &'static str = "P-256";
}

#[cfg(feature = "pkcs8")]
impl elliptic_curve::AlgorithmParameters for NistP256 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new("1.2.840.10045.3.1.7");
}

pub type CompressedPoint = GenericArray<u8, U33>;

pub type FieldBytes = elliptic_curve::FieldBytes<NistP256>;

pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<NistP256>;

#[cfg(feature = "arithmetic")]
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<NistP256>;

#[cfg(feature = "arithmetic")]
pub type PublicKey = elliptic_curve::PublicKey<NistP256>;

pub type SecretKey = elliptic_curve::SecretKey<NistP256>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for NistP256 {}

#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
pub type ScalarBits = elliptic_curve::ScalarBits<NistP256>;

#[cfg(feature = "voprf")]
#[cfg_attr(docsrs, doc(cfg(feature = "voprf")))]
impl elliptic_curve::VoprfParameters for NistP256 {
    const ID: u16 = 0x0003;

    type Hash = sha2::Sha256;
}
