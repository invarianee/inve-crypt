#![allow(non_snake_case)]

use backend::vector::BASEPOINT_ODD_LOOKUP_TABLE;
use backend::vector::{CachedPoint, ExtendedPoint};
use edwards::EdwardsPoint;
use scalar::Scalar;
use traits::Identity;
use window::NafLookupTable5;

pub fn mul(a: &Scalar, A: &EdwardsPoint, b: &Scalar) -> EdwardsPoint {
    let a_naf = a.non_adjacent_form(5);
    let b_naf = b.non_adjacent_form(8);

    let mut i: usize = 255;
    for j in (0..256).rev() {
        i = j;
        if a_naf[i] != 0 || b_naf[i] != 0 {
            break;
        }
    }

    let table_A = NafLookupTable5::<CachedPoint>::from(A);
    let table_B = &BASEPOINT_ODD_LOOKUP_TABLE;

    let mut Q = ExtendedPoint::identity();

    loop {
        Q = Q.double();

        if a_naf[i] > 0 {
            Q = &Q + &table_A.select(a_naf[i] as usize);
        } else if a_naf[i] < 0 {
            Q = &Q - &table_A.select(-a_naf[i] as usize);
        }

        if b_naf[i] > 0 {
            Q = &Q + &table_B.select(b_naf[i] as usize);
        } else if b_naf[i] < 0 {
            Q = &Q - &table_B.select(-b_naf[i] as usize);
        }

        if i == 0 {
            break;
        }
        i -= 1;
    }

    Q.into()
}
