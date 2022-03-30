#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
pub mod pkcs8;

pub use signature::{self, Error};

#[cfg(feature = "pkcs8")]
pub use crate::pkcs8::KeypairBytes;

use core::{fmt, str};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serde::{de, ser, Deserialize, Serialize};
#[cfg(feature = "serde_bytes")]
use serde_bytes_crate as serde_bytes;

#[deprecated(since = "1.3.0", note = "use ed25519::Signature::BYTE_SIZE instead")]
pub const SIGNATURE_LENGTH: usize = Signature::BYTE_SIZE;

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Signature([u8; Signature::BYTE_SIZE]);

impl Signature {
    pub const BYTE_SIZE: usize = 64;

    pub fn from_bytes(bytes: &[u8]) -> signature::Result<Self> {
        let result = bytes.try_into().map(Self).map_err(|_| Error::new())?;

        if result.0[Signature::BYTE_SIZE - 1] & 0b1110_0000 != 0 {
            return Err(Error::new());
        }

        Ok(result)
    }

    pub fn to_bytes(self) -> [u8; Self::BYTE_SIZE] {
        self.0
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    #[deprecated(since = "1.3.0", note = "use ed25519::Signature::from_bytes instead")]
    pub fn new(bytes: [u8; Self::BYTE_SIZE]) -> Self {
        Self::from_bytes(&bytes[..]).expect("invalid signature")
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> signature::Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Signature> for [u8; Signature::BYTE_SIZE] {
    fn from(sig: Signature) -> [u8; Signature::BYTE_SIZE] {
        sig.0
    }
}

impl From<&Signature> for [u8; Signature::BYTE_SIZE] {
    fn from(sig: &Signature) -> [u8; Signature::BYTE_SIZE] {
        sig.0
    }
}

impl From<[u8; Signature::BYTE_SIZE]> for Signature {
    fn from(bytes: [u8; Signature::BYTE_SIZE]) -> Signature {
        #[allow(deprecated)]
        Signature::new(bytes)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ed25519::Signature({})", self)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl str::FromStr for Signature {
    type Err = Error;

    fn from_str(hex: &str) -> signature::Result<Self> {
        if hex.as_bytes().len() != Signature::BYTE_SIZE * 2 {
            return Err(Error::new());
        }

        let mut upper_case = None;

        for &byte in hex.as_bytes() {
            match byte {
                b'0'..=b'9' => (),
                b'a'..=b'z' => match upper_case {
                    Some(true) => return Err(Error::new()),
                    Some(false) => (),
                    None => upper_case = Some(false),
                },
                b'A'..=b'Z' => match upper_case {
                    Some(true) => (),
                    Some(false) => return Err(Error::new()),
                    None => upper_case = Some(true),
                },
                _ => return Err(Error::new()),
            }
        }

        let mut result = [0u8; Self::BYTE_SIZE];
        for (digit, byte) in hex.as_bytes().chunks_exact(2).zip(result.iter_mut()) {
            *byte = str::from_utf8(digit)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or_else(Error::new)?;
        }

        Self::try_from(&result[..])
    }
}

#[cfg(feature = "serde")]
impl Serialize for Signature {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use ser::SerializeTuple;

        let mut seq = serializer.serialize_tuple(Signature::BYTE_SIZE)?;

        for byte in &self.0[..] {
            seq.serialize_element(byte)?;
        }

        seq.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ByteArrayVisitor;

        impl<'de> de::Visitor<'de> for ByteArrayVisitor {
            type Value = [u8; Signature::BYTE_SIZE];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bytestring of length 64")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[u8; Signature::BYTE_SIZE], A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                use de::Error;
                let mut arr = [0u8; Signature::BYTE_SIZE];

                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }

                Ok(arr)
            }
        }

        deserializer
            .deserialize_tuple(Signature::BYTE_SIZE, ByteArrayVisitor)
            .map(|bytes| bytes.into())
    }
}

#[cfg(feature = "serde_bytes")]
impl serde_bytes::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde_bytes")]
impl<'de> serde_bytes::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct ByteArrayVisitor;

        impl<'de> de::Visitor<'de> for ByteArrayVisitor {
            type Value = [u8; Signature::BYTE_SIZE];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bytestring of length 64")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                use de::Error;

                bytes
                    .try_into()
                    .map_err(|_| Error::invalid_length(bytes.len(), &self))
            }
        }

        deserializer
            .deserialize_bytes(ByteArrayVisitor)
            .map(Signature::from)
    }
}
