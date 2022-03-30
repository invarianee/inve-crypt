#[cfg(feature = "alloc")]
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub use rand_core;

pub mod ops;

#[cfg(feature = "sec1")]
pub mod sec1;

mod error;
mod point;
mod scalar;
mod secret_key;

#[cfg(feature = "arithmetic")]
mod arithmetic;
#[cfg(feature = "arithmetic")]
mod public_key;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

#[cfg(feature = "ecdh")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdh")))]
pub mod ecdh;

#[cfg(feature = "jwk")]
mod jwk;

#[cfg(feature = "hash2curve")]
#[cfg_attr(docsrs, doc(cfg(feature = "hash2curve")))]
pub mod hash2curve;

pub use crate::{
    error::{Error, Result},
    point::{
        AffineXCoordinate, DecompactPoint, DecompressPoint, PointCompaction, PointCompression,
    },
    scalar::{core::ScalarCore, IsHigh},
    secret_key::SecretKey,
};
pub use generic_array::{self, typenum::consts};
pub use inve_bigint as bigint;
pub use rand_core;
pub use subtle;
pub use zeroize;

#[cfg(feature = "arithmetic")]
pub use {
    crate::{
        arithmetic::{
            AffineArithmetic, PrimeCurveArithmetic, ProjectiveArithmetic, ScalarArithmetic,
        },
        public_key::PublicKey,
        scalar::{nonzero::NonZeroScalar, Scalar},
    },
    ff::{self, Field, PrimeField},
    group::{self, Group},
};

#[cfg(feature = "bits")]
pub use crate::scalar::ScalarBits;

#[cfg(feature = "jwk")]
pub use crate::jwk::{JwkEcKey, JwkParameters};

#[cfg(feature = "pkcs8")]
pub use ::sec1::pkcs8;

#[cfg(feature = "serde")]
pub use serde;

use core::fmt::Debug;
use generic_array::GenericArray;

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
pub const ALGORITHM_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new("1.2.840.10045.2.1");

pub trait Curve: 'static + Copy + Clone + Debug + Default + Eq + Ord + Send + Sync {
    type UInt: bigint::AddMod<Output = Self::UInt>
        + bigint::ArrayEncoding
        + bigint::Encoding
        + bigint::Integer
        + bigint::NegMod<Output = Self::UInt>
        + bigint::Random
        + bigint::RandomMod
        + bigint::SubMod<Output = Self::UInt>
        + zeroize::Zeroize;

    const ORDER: Self::UInt;
}

pub trait PrimeCurve: Curve {}

pub type FieldSize<C> = <<C as Curve>::UInt as bigint::ArrayEncoding>::ByteSize;

pub type FieldBytes<C> = GenericArray<u8, FieldSize<C>>;

#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
#[cfg(feature = "arithmetic")]
pub type AffinePoint<C> = <C as AffineArithmetic>::AffinePoint;

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub type ProjectivePoint<C> = <C as ProjectiveArithmetic>::ProjectivePoint;

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
pub trait AlgorithmParameters: Curve {
    const OID: pkcs8::ObjectIdentifier;

    fn algorithm_identifier() -> pkcs8::AlgorithmIdentifier<'static> {
        pkcs8::AlgorithmIdentifier {
            oid: ALGORITHM_OID,
            parameters: Some((&Self::OID).into()),
        }
    }
}

#[cfg(feature = "voprf")]
#[cfg_attr(docsrs, doc(cfg(feature = "voprf")))]
pub trait VoprfParameters: Curve {
    const ID: u16;

    type Hash: digest::Digest;
}
