#![allow(non_snake_case)]

use core::borrow::Borrow;

use subtle;

use scalar::Scalar;

pub trait Identity {
    fn identity() -> Self;
}

pub trait IsIdentity {
    fn is_identity(&self) -> bool;
}

impl<T> IsIdentity for T
where
    T: subtle::ConstantTimeEq + Identity,
{
    fn is_identity(&self) -> bool {
        self.ct_eq(&T::identity()).unwrap_u8() == 1u8
    }
}

pub trait BasepointTable {
    type Point;

    fn create(basepoint: &Self::Point) -> Self;

    fn basepoint(&self) -> Self::Point;

    fn basepoint_mul(&self, scalar: &Scalar) -> Self::Point;
}

pub trait MultiscalarMul {
    type Point;

    fn multiscalar_mul<I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Self::Point>;
}

pub trait VartimeMultiscalarMul {
    type Point;

    fn optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<Self::Point>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<Self::Point>>;

    fn vartime_multiscalar_mul<I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Self::Point>,
        Self::Point: Clone,
    {
        Self::optional_multiscalar_mul(
            scalars,
            points.into_iter().map(|P| Some(P.borrow().clone())),
        )
        .unwrap()
    }
}

pub trait VartimePrecomputedMultiscalarMul: Sized {
    type Point: Clone;

    fn new<I>(static_points: I) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Self::Point>;

    fn vartime_multiscalar_mul<I>(&self, static_scalars: I) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
    {
        use core::iter;

        Self::vartime_mixed_multiscalar_mul(
            self,
            static_scalars,
            iter::empty::<Scalar>(),
            iter::empty::<Self::Point>(),
        )
    }

    fn vartime_mixed_multiscalar_mul<I, J, K>(
        &self,
        static_scalars: I,
        dynamic_scalars: J,
        dynamic_points: K,
    ) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Scalar>,
        K: IntoIterator,
        K::Item: Borrow<Self::Point>,
    {
        Self::optional_mixed_multiscalar_mul(
            self,
            static_scalars,
            dynamic_scalars,
            dynamic_points.into_iter().map(|P| Some(P.borrow().clone())),
        )
        .unwrap()
    }

    fn optional_mixed_multiscalar_mul<I, J, K>(
        &self,
        static_scalars: I,
        dynamic_scalars: J,
        dynamic_points: K,
    ) -> Option<Self::Point>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Scalar>,
        K: IntoIterator<Item = Option<Self::Point>>;
}

pub(crate) trait ValidityCheck {
    fn is_valid(&self) -> bool;
}
