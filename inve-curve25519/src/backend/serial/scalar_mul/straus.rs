#![allow(non_snake_case)]

use core::borrow::Borrow;

use edwards::EdwardsPoint;
use scalar::Scalar;
use traits::MultiscalarMul;
use traits::VartimeMultiscalarMul;

#[allow(unused_imports)]
use prelude::*;

pub struct Straus {}

impl MultiscalarMul for Straus {
    type Point = EdwardsPoint;

    fn multiscalar_mul<I, J>(scalars: I, points: J) -> EdwardsPoint
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<EdwardsPoint>,
    {
        use zeroize::Zeroizing;

        use backend::serial::curve_models::ProjectiveNielsPoint;
        use traits::Identity;
        use window::LookupTable;

        let lookup_tables: Vec<_> = points
            .into_iter()
            .map(|point| LookupTable::<ProjectiveNielsPoint>::from(point.borrow()))
            .collect();

        let scalar_digits_vec: Vec<_> = scalars
            .into_iter()
            .map(|s| s.borrow().to_radix_16())
            .collect();
        let scalar_digits = Zeroizing::new(scalar_digits_vec);

        let mut Q = EdwardsPoint::identity();
        for j in (0..64).rev() {
            Q = Q.mul_by_pow_2(4);
            let it = scalar_digits.iter().zip(lookup_tables.iter());
            for (s_i, lookup_table_i) in it {
                let R_i = lookup_table_i.select(s_i[j]);
                Q = (&Q + &R_i).to_extended();
            }
        }

        Q
    }
}

impl VartimeMultiscalarMul for Straus {
    type Point = EdwardsPoint;

    fn optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<EdwardsPoint>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<EdwardsPoint>>,
    {
        use backend::serial::curve_models::{
            CompletedPoint, ProjectiveNielsPoint, ProjectivePoint,
        };
        use traits::Identity;
        use window::NafLookupTable5;

        let nafs: Vec<_> = scalars
            .into_iter()
            .map(|c| c.borrow().non_adjacent_form(5))
            .collect();

        let lookup_tables = points
            .into_iter()
            .map(|P_opt| P_opt.map(|P| NafLookupTable5::<ProjectiveNielsPoint>::from(&P)))
            .collect::<Option<Vec<_>>>()?;

        let mut r = ProjectivePoint::identity();

        for i in (0..256).rev() {
            let mut t: CompletedPoint = r.double();

            for (naf, lookup_table) in nafs.iter().zip(lookup_tables.iter()) {
                if naf[i] > 0 {
                    t = &t.to_extended() + &lookup_table.select(naf[i] as usize);
                } else if naf[i] < 0 {
                    t = &t.to_extended() - &lookup_table.select(-naf[i] as usize);
                }
            }

            r = t.to_projective();
        }

        Some(r.to_extended())
    }
}
