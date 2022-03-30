use crate::{
    bigint::Encoding as _,
    ops::{Invert, Reduce, ReduceNonZero},
    rand_core::{CryptoRng, RngCore},
    Curve, Error, FieldBytes, IsHigh, PrimeCurve, Result, Scalar, ScalarArithmetic, ScalarCore,
    SecretKey,
};
use base16ct::HexDisplay;
use core::{
    fmt,
    ops::{Deref, Mul, Neg},
    str,
};
use ff::{Field, PrimeField};
use generic_array::GenericArray;
use inve_bigint::{ArrayEncoding, Integer};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
#[derive(Clone)]
pub struct NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    scalar: Scalar<C>,
}

impl<C> NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    pub fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        loop {
            if let Some(result) = Self::new(Field::random(&mut rng)).into() {
                break result;
            }
        }
    }

    pub fn new(scalar: Scalar<C>) -> CtOption<Self> {
        CtOption::new(Self { scalar }, !scalar.is_zero())
    }

    pub fn from_repr(repr: FieldBytes<C>) -> CtOption<Self> {
        Scalar::<C>::from_repr(repr).and_then(Self::new)
    }

    pub fn from_uint(uint: C::UInt) -> CtOption<Self> {
        ScalarCore::new(uint).and_then(|scalar| Self::new(scalar.into()))
    }
}

impl<C> AsRef<Scalar<C>> for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    fn as_ref(&self) -> &Scalar<C> {
        &self.scalar
    }
}

impl<C> ConditionallySelectable for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            scalar: Scalar::<C>::conditional_select(&a.scalar, &b.scalar, choice),
        }
    }
}

impl<C> ConstantTimeEq for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.scalar.ct_eq(&other.scalar)
    }
}

impl<C> Copy for NonZeroScalar<C> where C: Curve + ScalarArithmetic {}

impl<C> Deref for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    type Target = Scalar<C>;

    fn deref(&self) -> &Scalar<C> {
        &self.scalar
    }
}

impl<C> From<NonZeroScalar<C>> for FieldBytes<C>
where
    C: Curve + ScalarArithmetic,
{
    fn from(scalar: NonZeroScalar<C>) -> FieldBytes<C> {
        Self::from(&scalar)
    }
}

impl<C> From<&NonZeroScalar<C>> for FieldBytes<C>
where
    C: Curve + ScalarArithmetic,
{
    fn from(scalar: &NonZeroScalar<C>) -> FieldBytes<C> {
        scalar.to_repr()
    }
}

impl<C> From<NonZeroScalar<C>> for ScalarCore<C>
where
    C: Curve + ScalarArithmetic,
{
    fn from(scalar: NonZeroScalar<C>) -> ScalarCore<C> {
        ScalarCore::from_be_bytes(scalar.to_repr()).unwrap()
    }
}

impl<C> From<&NonZeroScalar<C>> for ScalarCore<C>
where
    C: Curve + ScalarArithmetic,
{
    fn from(scalar: &NonZeroScalar<C>) -> ScalarCore<C> {
        ScalarCore::from_be_bytes(scalar.to_repr()).unwrap()
    }
}

impl<C> From<SecretKey<C>> for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    fn from(sk: SecretKey<C>) -> NonZeroScalar<C> {
        Self::from(&sk)
    }
}

impl<C> From<&SecretKey<C>> for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    fn from(sk: &SecretKey<C>) -> NonZeroScalar<C> {
        let scalar = sk.as_scalar_core().to_scalar();
        debug_assert!(!bool::from(scalar.is_zero()));
        Self { scalar }
    }
}

impl<C> Invert for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    type Output = Self;

    fn invert(&self) -> Self {
        Self {
            scalar: ff::Field::invert(&self.scalar).unwrap(),
        }
    }
}

impl<C> IsHigh for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    fn is_high(&self) -> Choice {
        self.scalar.is_high()
    }
}

impl<C> Neg for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    type Output = NonZeroScalar<C>;

    fn neg(self) -> NonZeroScalar<C> {
        let scalar = -self.scalar;
        debug_assert!(!bool::from(scalar.is_zero()));
        NonZeroScalar { scalar }
    }
}

impl<C> Mul<NonZeroScalar<C>> for NonZeroScalar<C>
where
    C: PrimeCurve + ScalarArithmetic,
{
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        Self::mul(self, &other)
    }
}

impl<C> Mul<&NonZeroScalar<C>> for NonZeroScalar<C>
where
    C: PrimeCurve + ScalarArithmetic,
{
    type Output = Self;

    fn mul(self, other: &Self) -> Self {
        let scalar = self.scalar * other.scalar;
        debug_assert!(!bool::from(scalar.is_zero()));
        NonZeroScalar { scalar }
    }
}

impl<C, I> Reduce<I> for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
    I: Integer + ArrayEncoding,
    Scalar<C>: ReduceNonZero<I>,
{
    fn from_uint_reduced(n: I) -> Self {
        Self::from_uint_reduced_nonzero(n)
    }
}

impl<C, I> ReduceNonZero<I> for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
    I: Integer + ArrayEncoding,
    Scalar<C>: ReduceNonZero<I>,
{
    fn from_uint_reduced_nonzero(n: I) -> Self {
        let scalar = Scalar::<C>::from_uint_reduced_nonzero(n);
        debug_assert!(!bool::from(scalar.is_zero()));
        Self::new(scalar).unwrap()
    }
}

impl<C> TryFrom<&[u8]> for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == C::UInt::BYTE_SIZE {
            Option::from(NonZeroScalar::from_repr(GenericArray::clone_from_slice(
                bytes,
            )))
            .ok_or(Error)
        } else {
            Err(Error)
        }
    }
}

impl<C> Zeroize for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    fn zeroize(&mut self) {
        self.scalar.zeroize();

        self.scalar = Scalar::<C>::one();
    }
}

impl<C> fmt::Display for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

impl<C> fmt::LowerHex for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", HexDisplay(&self.to_repr()))
    }
}

impl<C> fmt::UpperHex for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:}", HexDisplay(&self.to_repr()))
    }
}

impl<C> str::FromStr for NonZeroScalar<C>
where
    C: Curve + ScalarArithmetic,
{
    type Err = Error;

    fn from_str(hex: &str) -> Result<Self> {
        let mut bytes = FieldBytes::<C>::default();

        if base16ct::mixed::decode(hex, &mut bytes)?.len() == bytes.len() {
            Option::from(Self::from_repr(bytes)).ok_or(Error)
        } else {
            Err(Error)
        }
    }
}

#[cfg(all(test, feature = "dev"))]
mod tests {
    use crate::dev::{NonZeroScalar, Scalar};
    use ff::{Field, PrimeField};
    use hex_literal::hex;
    use zeroize::Zeroize;

    #[test]
    fn round_trip() {
        let bytes = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let scalar = NonZeroScalar::from_repr(bytes.into()).unwrap();
        assert_eq!(&bytes, scalar.to_repr().as_slice());
    }

    #[test]
    fn zeroize() {
        let mut scalar = NonZeroScalar::new(Scalar::from(42u64)).unwrap();
        scalar.zeroize();
        assert_eq!(*scalar, Scalar::one());
    }
}
