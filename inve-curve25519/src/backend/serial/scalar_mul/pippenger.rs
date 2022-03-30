#![allow(non_snake_case)]

use core::borrow::Borrow;

use edwards::EdwardsPoint;
use scalar::Scalar;
use traits::VartimeMultiscalarMul;

#[allow(unused_imports)]
use prelude::*;

pub struct Pippenger;

#[cfg(any(feature = "alloc", feature = "std"))]
impl VartimeMultiscalarMul for Pippenger {
    type Point = EdwardsPoint;

    fn optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<EdwardsPoint>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<EdwardsPoint>>,
    {
        use traits::Identity;

        let mut scalars = scalars.into_iter();
        let size = scalars.by_ref().size_hint().0;

        let w = if size < 500 {
            6
        } else if size < 800 {
            7
        } else {
            8
        };

        let max_digit: usize = 1 << w;
        let digits_count: usize = Scalar::to_radix_2w_size_hint(w);
        let buckets_count: usize = max_digit / 2;

        let scalars = scalars.map(|s| s.borrow().to_radix_2w(w));

        let points = points
            .into_iter()
            .map(|p| p.map(|P| P.to_projective_niels()));

        let scalars_points = scalars
            .zip(points)
            .map(|(s, maybe_p)| maybe_p.map(|p| (s, p)))
            .collect::<Option<Vec<_>>>()?;

        let mut buckets: Vec<_> = (0..buckets_count)
            .map(|_| EdwardsPoint::identity())
            .collect();

        let mut columns = (0..digits_count).rev().map(|digit_index| {
            for i in 0..buckets_count {
                buckets[i] = EdwardsPoint::identity();
            }

            for (digits, pt) in scalars_points.iter() {
                let digit = digits[digit_index] as i16;
                if digit > 0 {
                    let b = (digit - 1) as usize;
                    buckets[b] = (&buckets[b] + pt).to_extended();
                } else if digit < 0 {
                    let b = (-digit - 1) as usize;
                    buckets[b] = (&buckets[b] - pt).to_extended();
                }
            }

            let mut buckets_intermediate_sum = buckets[buckets_count - 1];
            let mut buckets_sum = buckets[buckets_count - 1];
            for i in (0..(buckets_count - 1)).rev() {
                buckets_intermediate_sum += buckets[i];
                buckets_sum += buckets_intermediate_sum;
            }

            buckets_sum
        });

        let hi_column = columns.next().unwrap();

        Some(columns.fold(hi_column, |total, p| total.mul_by_pow_2(w as u32) + p))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use constants;
    use scalar::Scalar;

    #[test]
    fn test_vartime_pippenger() {
        let mut n = 512;
        let x = Scalar::from(2128506u64).invert();
        let y = Scalar::from(4443282u64).invert();
        let points: Vec<_> = (0..n)
            .map(|i| constants::ED25519_BASEPOINT_POINT * Scalar::from(1 + i as u64))
            .collect();
        let scalars: Vec<_> = (0..n).map(|i| x + (Scalar::from(i as u64) * y)).collect();

        let premultiplied: Vec<EdwardsPoint> = scalars
            .iter()
            .zip(points.iter())
            .map(|(sc, pt)| sc * pt)
            .collect();

        while n > 0 {
            let scalars = &scalars[0..n].to_vec();
            let points = &points[0..n].to_vec();
            let control: EdwardsPoint = premultiplied[0..n].iter().sum();

            let subject = Pippenger::vartime_multiscalar_mul(scalars.clone(), points.clone());

            assert_eq!(subject.compress(), control.compress());

            n = n / 2;
        }
    }
}
