#![allow(non_snake_case)]

use backend::vector::{CachedPoint, ExtendedPoint};
use edwards::EdwardsPoint;
use scalar::Scalar;
use traits::Identity;
use window::LookupTable;

pub fn mul(point: &EdwardsPoint, scalar: &Scalar) -> EdwardsPoint {
    let lookup_table = LookupTable::<CachedPoint>::from(point);
    let scalar_digits = scalar.to_radix_16();
    let mut Q = ExtendedPoint::identity();
    for i in (0..64).rev() {
        Q = Q.mul_by_pow_2(4);
        Q = &Q + &lookup_table.select(scalar_digits[i]);
    }
    Q.into()
}
