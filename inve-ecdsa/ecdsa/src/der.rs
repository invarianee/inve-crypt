use crate::{Error, Result};
use core::{
    fmt,
    ops::{Add, Range},
};
use der::{asn1::UIntBytes, Decodable, Encodable};
use elliptic_curve::{
    bigint::Encoding as _,
    consts::U9,
    generic_array::{ArrayLength, GenericArray},
    FieldSize, PrimeCurve,
};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

pub type MaxOverhead = U9;

pub type MaxSize<C> = <<FieldSize<C> as Add>::Output as Add<MaxOverhead>>::Output;

type SignatureBytes<C> = GenericArray<u8, MaxSize<C>>;

pub struct Signature<C>
where
    C: PrimeCurve,
    MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    bytes: SignatureBytes<C>,

    r_range: Range<usize>,

    s_range: Range<usize>,
}

impl<C> signature::Signature for Signature<C>
where
    C: PrimeCurve,
    MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bytes.try_into()
    }
}

#[allow(clippy::len_without_is_empty)]
impl<C> Signature<C>
where
    C: PrimeCurve,
    MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    pub fn len(&self) -> usize {
        self.s_range.end
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.len()]
    }

    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.as_bytes().to_vec().into_boxed_slice()
    }

    pub(crate) fn from_scalar_bytes(r: &[u8], s: &[u8]) -> der::Result<Self> {
        let r = UIntBytes::new(r)?;
        let s = UIntBytes::new(s)?;

        let mut bytes = SignatureBytes::<C>::default();
        let mut encoder = der::Encoder::new(&mut bytes);

        encoder.sequence((r.encoded_len()? + s.encoded_len()?)?, |seq| {
            seq.encode(&r)?;
            seq.encode(&s)
        })?;

        encoder
            .finish()?
            .try_into()
            .map_err(|_| der::Tag::Sequence.value_error())
    }

    pub(crate) fn r(&self) -> &[u8] {
        &self.bytes[self.r_range.clone()]
    }

    pub(crate) fn s(&self) -> &[u8] {
        &self.bytes[self.s_range.clone()]
    }
}

impl<C> AsRef<[u8]> for Signature<C>
where
    C: PrimeCurve,
    MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C> fmt::Debug for Signature<C>
where
    C: PrimeCurve,
    MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("asn1::Signature")
            .field("r", &self.r())
            .field("s", &self.s())
            .finish()
    }
}

impl<C> TryFrom<&[u8]> for Signature<C>
where
    C: PrimeCurve,
    MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        let (r, s) = der::Decoder::new(input)
            .and_then(|mut decoder| {
                decoder.sequence(|decoder| {
                    Ok((UIntBytes::decode(decoder)?, UIntBytes::decode(decoder)?))
                })
            })
            .map_err(|_| Error::new())?;

        if r.as_bytes().len() > C::UInt::BYTE_SIZE || s.as_bytes().len() > C::UInt::BYTE_SIZE {
            return Err(Error::new());
        }

        let r_range = find_scalar_range(input, r.as_bytes())?;
        let s_range = find_scalar_range(input, s.as_bytes())?;

        if s_range.end != input.len() {
            return Err(Error::new());
        }

        let mut bytes = SignatureBytes::<C>::default();
        bytes[..s_range.end].copy_from_slice(input);

        Ok(Signature {
            bytes,
            r_range,
            s_range,
        })
    }
}

impl<C> TryFrom<Signature<C>> for super::Signature<C>
where
    C: PrimeCurve,
    MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(sig: Signature<C>) -> Result<super::Signature<C>> {
        let mut bytes = super::SignatureBytes::<C>::default();
        let r_begin = C::UInt::BYTE_SIZE.saturating_sub(sig.r().len());
        let s_begin = bytes.len().saturating_sub(sig.s().len());
        bytes[r_begin..C::UInt::BYTE_SIZE].copy_from_slice(sig.r());
        bytes[s_begin..].copy_from_slice(sig.s());
        Self::try_from(bytes.as_slice())
    }
}

fn find_scalar_range(outer: &[u8], inner: &[u8]) -> Result<Range<usize>> {
    let outer_start = outer.as_ptr() as usize;
    let inner_start = inner.as_ptr() as usize;
    let start = inner_start
        .checked_sub(outer_start)
        .ok_or_else(Error::new)?;
    let end = start.checked_add(inner.len()).ok_or_else(Error::new)?;
    Ok(Range { start, end })
}

#[cfg(all(feature = "digest", feature = "hazmat"))]
impl<C> signature::PrehashSignature for Signature<C>
where
    C: PrimeCurve + crate::hazmat::DigestPrimitive,
    MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    type Digest = C::Digest;
}

#[cfg(all(test, feature = "arithmetic"))]
mod tests {
    use elliptic_curve::dev::MockCurve;
    use signature::Signature as _;

    type Signature = crate::Signature<MockCurve>;

    const EXAMPLE_SIGNATURE: [u8; 64] = [
        0xf3, 0xac, 0x80, 0x61, 0xb5, 0x14, 0x79, 0x5b, 0x88, 0x43, 0xe3, 0xd6, 0x62, 0x95, 0x27,
        0xed, 0x2a, 0xfd, 0x6b, 0x1f, 0x6a, 0x55, 0x5a, 0x7a, 0xca, 0xbb, 0x5e, 0x6f, 0x79, 0xc8,
        0xc2, 0xac, 0x8b, 0xf7, 0x78, 0x19, 0xca, 0x5, 0xa6, 0xb2, 0x78, 0x6c, 0x76, 0x26, 0x2b,
        0xf7, 0x37, 0x1c, 0xef, 0x97, 0xb2, 0x18, 0xe9, 0x6f, 0x17, 0x5a, 0x3c, 0xcd, 0xda, 0x2a,
        0xcc, 0x5, 0x89, 0x3,
    ];

    #[test]
    fn test_fixed_to_asn1_signature_roundtrip() {
        let signature1 = Signature::from_bytes(&EXAMPLE_SIGNATURE).unwrap();

        let asn1_signature = signature1.to_der();
        let signature2 = Signature::from_der(asn1_signature.as_ref()).unwrap();

        assert_eq!(signature1, signature2);
    }

    #[test]
    fn test_asn1_too_short_signature() {
        assert!(Signature::from_der(&[]).is_err());
        assert!(Signature::from_der(&[der::Tag::Sequence.into()]).is_err());
        assert!(Signature::from_der(&[der::Tag::Sequence.into(), 0x00]).is_err());
        assert!(Signature::from_der(&[
            der::Tag::Sequence.into(),
            0x03,
            der::Tag::Integer.into(),
            0x01,
            0x01
        ])
        .is_err());
    }

    #[test]
    fn test_asn1_non_der_signature() {
        assert!(Signature::from_der(&[
            der::Tag::Sequence.into(),
            0x06,
            der::Tag::Integer.into(),
            0x01,
            0x01,
            der::Tag::Integer.into(),
            0x01,
            0x01,
        ])
        .is_ok());

        assert!(Signature::from_der(&[
            der::Tag::Sequence.into(),
            0x81,
            0x06,
            der::Tag::Integer.into(),
            0x01,
            0x01,
            der::Tag::Integer.into(),
            0x01,
            0x01,
        ])
        .is_err());
    }
}
