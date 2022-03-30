use subtle::Choice;

pub(crate) mod core;

#[cfg(feature = "arithmetic")]
pub(crate) mod nonzero;

#[cfg(feature = "arithmetic")]
use crate::ScalarArithmetic;

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub type Scalar<C> = <C as ScalarArithmetic>::Scalar;

#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
pub type ScalarBits<C> = ff::FieldBits<<Scalar<C> as ff::PrimeFieldBits>::ReprBits>;

pub trait IsHigh {
    fn is_high(&self) -> Choice;
}
