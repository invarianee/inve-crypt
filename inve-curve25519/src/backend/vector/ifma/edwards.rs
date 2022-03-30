#![allow(non_snake_case)]

use traits::Identity;

use std::ops::{Add, Neg, Sub};

use subtle::Choice;
use subtle::ConditionallySelectable;

use edwards;
use window::{LookupTable, NafLookupTable5, NafLookupTable8};

use super::constants;
use super::field::{F51x4Reduced, F51x4Unreduced, Lanes, Shuffle};

#[derive(Copy, Clone, Debug)]
pub struct ExtendedPoint(pub(super) F51x4Unreduced);

#[derive(Copy, Clone, Debug)]
pub struct CachedPoint(pub(super) F51x4Reduced);

impl From<edwards::EdwardsPoint> for ExtendedPoint {
    fn from(P: edwards::EdwardsPoint) -> ExtendedPoint {
        ExtendedPoint(F51x4Unreduced::new(&P.X, &P.Y, &P.Z, &P.T))
    }
}

impl From<ExtendedPoint> for edwards::EdwardsPoint {
    fn from(P: ExtendedPoint) -> edwards::EdwardsPoint {
        let reduced = F51x4Reduced::from(P.0);
        let tmp = F51x4Unreduced::from(reduced).split();
        edwards::EdwardsPoint {
            X: tmp[0],
            Y: tmp[1],
            Z: tmp[2],
            T: tmp[3],
        }
    }
}

impl From<ExtendedPoint> for CachedPoint {
    fn from(P: ExtendedPoint) -> CachedPoint {
        let mut x = P.0;

        x = x.blend(&x.diff_sum(), Lanes::AB);
        x = &F51x4Reduced::from(x) * (121666, 121666, 2 * 121666, 2 * 121665);
        x = x.blend(&x.negate_lazy(), Lanes::D);

        CachedPoint(F51x4Reduced::from(x))
    }
}

impl Default for ExtendedPoint {
    fn default() -> ExtendedPoint {
        ExtendedPoint::identity()
    }
}

impl Identity for ExtendedPoint {
    fn identity() -> ExtendedPoint {
        constants::EXTENDEDPOINT_IDENTITY
    }
}

impl ExtendedPoint {
    pub fn double(&self) -> ExtendedPoint {
        let mut tmp0 = self.0.shuffle(Shuffle::BADC);

        let mut tmp1 = (self.0 + tmp0).shuffle(Shuffle::ABAB);

        tmp0 = self.0.blend(&tmp1, Lanes::D);

        tmp1 = F51x4Reduced::from(tmp0).square();

        let zero = F51x4Unreduced::zero();

        let S1_S1_S1_S1 = tmp1.shuffle(Shuffle::AAAA);
        let S2_S2_S2_S2 = tmp1.shuffle(Shuffle::BBBB);

        let S2_S2_S2_S4 = S2_S2_S2_S2.blend(&tmp1, Lanes::D).negate_lazy();

        tmp0 = S1_S1_S1_S1 + zero.blend(&(tmp1 + tmp1), Lanes::C);
        tmp0 = tmp0 + zero.blend(&S2_S2_S2_S2, Lanes::AD);
        tmp0 = tmp0 + zero.blend(&S2_S2_S2_S4, Lanes::BCD);

        let tmp2 = F51x4Reduced::from(tmp0);

        ExtendedPoint(&tmp2.shuffle(Shuffle::DBBD) * &tmp2.shuffle(Shuffle::CACA))
    }

    pub fn mul_by_pow_2(&self, k: u32) -> ExtendedPoint {
        let mut tmp: ExtendedPoint = *self;
        for _ in 0..k {
            tmp = tmp.double();
        }
        tmp
    }
}

impl<'a, 'b> Add<&'b CachedPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    fn add(self, other: &'b CachedPoint) -> ExtendedPoint {
        let mut tmp = self.0;

        tmp = tmp.blend(&tmp.diff_sum(), Lanes::AB);

        tmp = &F51x4Reduced::from(tmp) * &other.0;

        tmp = tmp.shuffle(Shuffle::ABDC);

        let tmp = F51x4Reduced::from(tmp.diff_sum());

        let t0 = tmp.shuffle(Shuffle::ADDA);
        let t1 = tmp.shuffle(Shuffle::CBCB);

        ExtendedPoint(&t0 * &t1)
    }
}

impl Default for CachedPoint {
    fn default() -> CachedPoint {
        CachedPoint::identity()
    }
}

impl Identity for CachedPoint {
    fn identity() -> CachedPoint {
        constants::CACHEDPOINT_IDENTITY
    }
}

impl ConditionallySelectable for CachedPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        CachedPoint(F51x4Reduced::conditional_select(&a.0, &b.0, choice))
    }

    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        self.0.conditional_assign(&other.0, choice);
    }
}

impl<'a> Neg for &'a CachedPoint {
    type Output = CachedPoint;

    fn neg(self) -> CachedPoint {
        let swapped = self.0.shuffle(Shuffle::BACD);
        CachedPoint(swapped.blend(&(-self.0), Lanes::D))
    }
}

impl<'a, 'b> Sub<&'b CachedPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    fn sub(self, other: &'b CachedPoint) -> ExtendedPoint {
        self + &(-other)
    }
}

impl<'a> From<&'a edwards::EdwardsPoint> for LookupTable<CachedPoint> {
    fn from(point: &'a edwards::EdwardsPoint) -> Self {
        let P = ExtendedPoint::from(*point);
        let mut points = [CachedPoint::from(P); 8];
        for i in 0..7 {
            points[i + 1] = (&P + &points[i]).into();
        }
        LookupTable(points)
    }
}

impl<'a> From<&'a edwards::EdwardsPoint> for NafLookupTable5<CachedPoint> {
    fn from(point: &'a edwards::EdwardsPoint) -> Self {
        let A = ExtendedPoint::from(*point);
        let mut Ai = [CachedPoint::from(A); 8];
        let A2 = A.double();
        for i in 0..7 {
            Ai[i + 1] = (&A2 + &Ai[i]).into();
        }
        NafLookupTable5(Ai)
    }
}

impl<'a> From<&'a edwards::EdwardsPoint> for NafLookupTable8<CachedPoint> {
    fn from(point: &'a edwards::EdwardsPoint) -> Self {
        let A = ExtendedPoint::from(*point);
        let mut Ai = [CachedPoint::from(A); 64];
        let A2 = A.double();
        for i in 0..63 {
            Ai[i + 1] = (&A2 + &Ai[i]).into();
        }
        NafLookupTable8(Ai)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn addition_test_helper(P: edwards::EdwardsPoint, Q: edwards::EdwardsPoint) {
        let cached_Q = CachedPoint::from(ExtendedPoint::from(Q));
        let R_vector: edwards::EdwardsPoint = (&ExtendedPoint::from(P) + &cached_Q).into();
        let S_vector: edwards::EdwardsPoint = (&ExtendedPoint::from(P) - &cached_Q).into();

        println!("Testing point addition:");
        println!("P = {:?}", P);
        println!("Q = {:?}", Q);
        println!("cached Q = {:?}", cached_Q);
        println!("R = P + Q = {:?}", &P + &Q);
        println!("R_vector = {:?}", R_vector);
        println!("S = P - Q = {:?}", &P - &Q);
        println!("S_vector = {:?}", S_vector);
        assert_eq!(R_vector.compress(), (&P + &Q).compress());
        assert_eq!(S_vector.compress(), (&P - &Q).compress());
        println!("OK!\n");
    }

    #[test]
    fn vector_addition_vs_serial_addition_vs_edwards_extendedpoint() {
        use constants;
        use scalar::Scalar;

        println!("Testing id +- id");
        let P = edwards::EdwardsPoint::identity();
        let Q = edwards::EdwardsPoint::identity();
        addition_test_helper(P, Q);

        println!("Testing id +- B");
        let P = edwards::EdwardsPoint::identity();
        let Q = constants::ED25519_BASEPOINT_POINT;
        addition_test_helper(P, Q);

        println!("Testing B +- B");
        let P = constants::ED25519_BASEPOINT_POINT;
        let Q = constants::ED25519_BASEPOINT_POINT;
        addition_test_helper(P, Q);

        println!("Testing B +- kB");
        let P = constants::ED25519_BASEPOINT_POINT;
        let Q = &constants::ED25519_BASEPOINT_TABLE * &Scalar::from(8475983829u64);
        addition_test_helper(P, Q);
    }

    fn doubling_test_helper(P: edwards::EdwardsPoint) {
        let R2: edwards::EdwardsPoint = ExtendedPoint::from(P).double().into();
        println!("Testing point doubling:");
        println!("P = {:?}", P);
        println!("(vector) R2 = {:?}", R2);
        println!("P + P = {:?}", &P + &P);
        assert_eq!(R2.compress(), (&P + &P).compress());
        println!("OK!\n");
    }

    #[test]
    fn vector_doubling_vs_serial_doubling_vs_edwards_extendedpoint() {
        use constants;
        use scalar::Scalar;

        println!("Testing [2]id");
        let P = edwards::EdwardsPoint::identity();
        doubling_test_helper(P);

        println!("Testing [2]B");
        let P = constants::ED25519_BASEPOINT_POINT;
        doubling_test_helper(P);

        println!("Testing [2]([k]B)");
        let P = &constants::ED25519_BASEPOINT_TABLE * &Scalar::from(8475983829u64);
        doubling_test_helper(P);
    }
}
