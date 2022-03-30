#[cfg(feature = "alloc")]
extern crate alloc;

mod recovery;

#[cfg(feature = "der")]
#[cfg_attr(docsrs, doc(cfg(feature = "der")))]
pub mod der;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

#[cfg(feature = "hazmat")]
#[cfg_attr(docsrs, doc(cfg(feature = "hazmat")))]
pub mod hazmat;

#[cfg(feature = "sign")]
mod sign;

#[cfg(feature = "verify")]
mod verify;

pub use crate::recovery::RecoveryId;

pub use elliptic_curve::{self, sec1::EncodedPoint, PrimeCurve};

pub use signature::{self, Error, Result};

#[cfg(feature = "sign")]
#[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
pub use crate::sign::SigningKey;

#[cfg(feature = "verify")]
#[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
pub use crate::verify::VerifyingKey;

use core::{
    fmt::{self, Debug},
    ops::Add,
};
use elliptic_curve::{
    bigint::Encoding as _,
    generic_array::{sequence::Concat, ArrayLength, GenericArray},
    FieldBytes, FieldSize, ScalarCore,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "arithmetic")]
use {
    core::str,
    elliptic_curve::{ff::PrimeField, IsHigh, NonZeroScalar, ScalarArithmetic},
};

#[cfg(feature = "serde")]
use elliptic_curve::serde::{ser, Serialize};

#[cfg(all(feature = "arithmetic", feature = "serde"))]
use elliptic_curve::serde::{de, Deserialize};

pub type SignatureSize<C> = <FieldSize<C> as Add>::Output;

pub type SignatureBytes<C> = GenericArray<u8, SignatureSize<C>>;

#[derive(Clone, Eq, PartialEq)]
pub struct Signature<C: PrimeCurve>
where
    SignatureSize<C>: ArrayLength<u8>,
{
    bytes: SignatureBytes<C>,
}

impl<C> Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    #[cfg(feature = "der")]
    #[cfg_attr(docsrs, doc(cfg(feature = "der")))]
    pub fn from_der(bytes: &[u8]) -> Result<Self>
    where
        der::MaxSize<C>: ArrayLength<u8>,
        <FieldSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
    {
        der::Signature::<C>::try_from(bytes).and_then(Self::try_from)
    }

    pub fn from_scalars(r: impl Into<FieldBytes<C>>, s: impl Into<FieldBytes<C>>) -> Result<Self> {
        Self::try_from(r.into().concat(s.into()).as_slice())
    }

    pub fn split_bytes(&self) -> (FieldBytes<C>, FieldBytes<C>) {
        let (r_bytes, s_bytes) = self.bytes.split_at(C::UInt::BYTE_SIZE);

        (
            GenericArray::clone_from_slice(r_bytes),
            GenericArray::clone_from_slice(s_bytes),
        )
    }

    #[cfg(feature = "der")]
    #[cfg_attr(docsrs, doc(cfg(feature = "der")))]
    pub fn to_der(&self) -> der::Signature<C>
    where
        der::MaxSize<C>: ArrayLength<u8>,
        <FieldSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
    {
        let (r, s) = self.bytes.split_at(C::UInt::BYTE_SIZE);
        der::Signature::from_scalar_bytes(r, s).expect("DER encoding error")
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
impl<C> Signature<C>
where
    C: PrimeCurve + ScalarArithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    pub fn r(&self) -> NonZeroScalar<C> {
        NonZeroScalar::try_from(self.split_bytes().0.as_slice())
            .expect("r-component ensured valid in constructor")
    }

    pub fn s(&self) -> NonZeroScalar<C> {
        NonZeroScalar::try_from(self.split_bytes().1.as_slice())
            .expect("s-component ensured valid in constructor")
    }

    pub fn split_scalars(&self) -> (NonZeroScalar<C>, NonZeroScalar<C>) {
        (self.r(), self.s())
    }

    pub fn normalize_s(&self) -> Option<Self> {
        let s = self.s();

        if s.is_high().into() {
            let neg_s = -s;
            let mut result = self.clone();
            result.bytes[C::UInt::BYTE_SIZE..].copy_from_slice(&neg_s.to_repr());
            Some(result)
        } else {
            None
        }
    }
}

impl<C> signature::Signature for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from(bytes)
    }
}

impl<C> AsRef<[u8]> for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl<C> Copy for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
    <SignatureSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C> Debug for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ecdsa::Signature<{:?}>({:?})",
            C::default(),
            self.as_ref()
        )
    }
}

impl<C> TryFrom<&[u8]> for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != C::UInt::BYTE_SIZE * 2 {
            return Err(Error::new());
        }

        for scalar_bytes in bytes.chunks_exact(C::UInt::BYTE_SIZE) {
            let scalar = ScalarCore::<C>::from_be_slice(scalar_bytes).map_err(|_| Error::new())?;

            if scalar.is_zero().into() {
                return Err(Error::new());
            }
        }

        Ok(Self {
            bytes: GenericArray::clone_from_slice(bytes),
        })
    }
}

impl<C> fmt::Display for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

impl<C> fmt::LowerHex for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<C> fmt::UpperHex for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
impl<C> str::FromStr for Signature<C>
where
    C: PrimeCurve + ScalarArithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Err = Error;

    fn from_str(hex: &str) -> Result<Self> {
        if hex.as_bytes().len() != C::UInt::BYTE_SIZE * 4 {
            return Err(Error::new());
        }

        if !hex
            .as_bytes()
            .iter()
            .all(|&byte| matches!(byte, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'))
        {
            return Err(Error::new());
        }

        let (r_hex, s_hex) = hex.split_at(C::UInt::BYTE_SIZE * 2);

        let r = r_hex
            .parse::<NonZeroScalar<C>>()
            .map_err(|_| Error::new())?;

        let s = s_hex
            .parse::<NonZeroScalar<C>>()
            .map_err(|_| Error::new())?;

        Self::from_scalars(r, s)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<C> Serialize for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    #[cfg(not(feature = "alloc"))]
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.as_ref().serialize(serializer)
    }

    #[cfg(feature = "alloc")]
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use alloc::string::ToString;
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            self.as_ref().serialize(serializer)
        }
    }
}

#[cfg(all(feature = "arithmetic", feature = "serde"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "arithmetic", feature = "serde"))))]
impl<'de, C> Deserialize<'de> for Signature<C>
where
    C: PrimeCurve + ScalarArithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    #[cfg(not(feature = "alloc"))]
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        use de::Error;
        <&[u8]>::deserialize(deserializer)
            .and_then(|bytes| Self::try_from(bytes).map_err(D::Error::custom))
    }

    #[cfg(feature = "alloc")]
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        use de::Error;
        if deserializer.is_human_readable() {
            <&str>::deserialize(deserializer)?
                .parse()
                .map_err(D::Error::custom)
        } else {
            <&[u8]>::deserialize(deserializer)
                .and_then(|bytes| Self::try_from(bytes).map_err(D::Error::custom))
        }
    }
}
