#![allow(non_snake_case)]

use backend::serial::curve_models::ProjectiveNielsPoint;
use edwards::EdwardsPoint;
use scalar::Scalar;
use traits::Identity;
use window::LookupTable;

pub(crate) fn mul(point: &EdwardsPoint, scalar: &Scalar) -> EdwardsPoint {
    let lookup_table = LookupTable::<ProjectiveNielsPoint>::from(point);
    let scalar_digits = scalar.to_radix_16();
    let mut tmp2;
    let mut tmp3 = EdwardsPoint::identity();
    let mut tmp1 = &tmp3 + &lookup_table.select(scalar_digits[63]);
    for i in (0..63).rev() {
        tmp2 = tmp1.to_projective();
        tmp1 = tmp2.double();
        tmp2 = tmp1.to_projective();
        tmp1 = tmp2.double();
        tmp2 = tmp1.to_projective();
        tmp1 = tmp2.double();
        tmp2 = tmp1.to_projective();
        tmp1 = tmp2.double();
        tmp3 = tmp1.to_extended();
        tmp1 = &tmp3 + &lookup_table.select(scalar_digits[i]);
    }
    tmp1.to_extended()
}
