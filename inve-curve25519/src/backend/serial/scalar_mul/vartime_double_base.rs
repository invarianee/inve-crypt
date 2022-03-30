#![allow(non_snake_case)]

use backend::serial::curve_models::{ProjectiveNielsPoint, ProjectivePoint};
use constants;
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

    let table_A = NafLookupTable5::<ProjectiveNielsPoint>::from(A);
    let table_B = &constants::AFFINE_ODD_MULTIPLES_OF_BASEPOINT;

    let mut r = ProjectivePoint::identity();
    loop {
        let mut t = r.double();

        if a_naf[i] > 0 {
            t = &t.to_extended() + &table_A.select(a_naf[i] as usize);
        } else if a_naf[i] < 0 {
            t = &t.to_extended() - &table_A.select(-a_naf[i] as usize);
        }

        if b_naf[i] > 0 {
            t = &t.to_extended() + &table_B.select(b_naf[i] as usize);
        } else if b_naf[i] < 0 {
            t = &t.to_extended() - &table_B.select(-b_naf[i] as usize);
        }

        r = t.to_projective();

        if i == 0 {
            break;
        }
        i -= 1;
    }

    r.to_extended()
}
