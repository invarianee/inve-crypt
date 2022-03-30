use crate::arithmetic::{
    scalar::{Scalar, WideScalar},
    ProjectivePoint,
};
use core::ops::{Mul, MulAssign};
use elliptic_curve::{
    ops::LinearCombination,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    IsHigh,
};

#[derive(Copy, Clone, Default)]
struct LookupTable([ProjectivePoint; 8]);

impl From<&ProjectivePoint> for LookupTable {
    fn from(p: &ProjectivePoint) -> Self {
        let mut points = [*p; 8];
        for j in 0..7 {
            points[j + 1] = p + &points[j];
        }
        LookupTable(points)
    }
}

impl LookupTable {
    pub fn select(&self, x: i8) -> ProjectivePoint {
        debug_assert!(x >= -8);
        debug_assert!(x <= 8);

        let xmask = x >> 7;
        let xabs = (x + xmask) ^ xmask;

        let mut t = ProjectivePoint::IDENTITY;
        for j in 1..9 {
            let c = (xabs as u8).ct_eq(&(j as u8));
            t.conditional_assign(&self.0[j - 1], c);
        }

        let neg_mask = Choice::from((xmask & 1) as u8);
        t.conditional_assign(&-t, neg_mask);

        t
    }
}

const MINUS_LAMBDA: Scalar = Scalar::from_bytes_unchecked(&[
    0xac, 0x9c, 0x52, 0xb3, 0x3f, 0xa3, 0xcf, 0x1f, 0x5a, 0xd9, 0xe3, 0xfd, 0x77, 0xed, 0x9b, 0xa4,
    0xa8, 0x80, 0xb9, 0xfc, 0x8e, 0xc7, 0x39, 0xc2, 0xe0, 0xcf, 0xc8, 0x10, 0xb5, 0x12, 0x83, 0xcf,
]);

const MINUS_B1: Scalar = Scalar::from_bytes_unchecked(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc3,
]);

const MINUS_B2: Scalar = Scalar::from_bytes_unchecked(&[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0x8a, 0x28, 0x0a, 0xc5, 0x07, 0x74, 0x34, 0x6d, 0xd7, 0x65, 0xcd, 0xa8, 0x3d, 0xb1, 0x56, 0x2c,
]);

const G1: Scalar = Scalar::from_bytes_unchecked(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x86,
    0xd2, 0x21, 0xa7, 0xd4, 0x6b, 0xcd, 0xe8, 0x6c, 0x90, 0xe4, 0x92, 0x84, 0xeb, 0x15, 0x3d, 0xab,
]);

const G2: Scalar = Scalar::from_bytes_unchecked(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe4, 0x43,
    0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc4, 0x22, 0x12,
]);

fn decompose_scalar(k: &Scalar) -> (Scalar, Scalar) {
    let c1 = WideScalar::mul_shift_vartime(k, &G1, 272) * MINUS_B1;
    let c2 = WideScalar::mul_shift_vartime(k, &G2, 272) * MINUS_B2;
    let r2 = c1 + c2;
    let r1 = k + r2 * MINUS_LAMBDA;

    (r1, r2)
}

#[derive(Copy, Clone)]
struct Radix16Decomposition([i8; 33]);

impl Radix16Decomposition {
    fn new(x: &Scalar) -> Self {
        debug_assert!((x >> 128).is_zero().unwrap_u8() == 1);

        let mut output = [0i8; 33];

        let bytes = x.to_bytes();
        for i in 0..16 {
            output[2 * i] = (bytes[31 - i] & 0xf) as i8;
            output[2 * i + 1] = ((bytes[31 - i] >> 4) & 0xf) as i8;
        }

        for i in 0..32 {
            let carry = (output[i] + 8) >> 4;
            output[i] -= carry << 4;
            output[i + 1] += carry;
        }

        Self(output)
    }
}

impl Default for Radix16Decomposition {
    fn default() -> Self {
        Self([0i8; 33])
    }
}

fn static_map<T: Copy, V: Copy, const N: usize>(
    f: impl Fn(T) -> V,
    x: &[T; N],
    default: V,
) -> [V; N] {
    let mut res = [default; N];
    for i in 0..N {
        res[i] = f(x[i]);
    }
    res
}

fn static_zip_map<T: Copy, S: Copy, V: Copy, const N: usize>(
    f: impl Fn(T, S) -> V,
    x: &[T; N],
    y: &[S; N],
    default: V,
) -> [V; N] {
    let mut res = [default; N];
    for i in 0..N {
        res[i] = f(x[i], y[i]);
    }
    res
}

#[inline(always)]
fn lincomb_generic<const N: usize>(xs: &[ProjectivePoint; N], ks: &[Scalar; N]) -> ProjectivePoint {
    let rs = static_map(
        |k| decompose_scalar(&k),
        ks,
        (Scalar::default(), Scalar::default()),
    );
    let r1s = static_map(|(r1, _r2)| r1, &rs, Scalar::default());
    let r2s = static_map(|(_r1, r2)| r2, &rs, Scalar::default());

    let xs_beta = static_map(|x| x.endomorphism(), xs, ProjectivePoint::default());

    let r1_signs = static_map(|r| r.is_high(), &r1s, Choice::from(0u8));
    let r2_signs = static_map(|r| r.is_high(), &r2s, Choice::from(0u8));

    let r1s_c = static_zip_map(
        |r, r_sign| Scalar::conditional_select(&r, &-r, r_sign),
        &r1s,
        &r1_signs,
        Scalar::default(),
    );
    let r2s_c = static_zip_map(
        |r, r_sign| Scalar::conditional_select(&r, &-r, r_sign),
        &r2s,
        &r2_signs,
        Scalar::default(),
    );

    let tables1 = static_zip_map(
        |x, r_sign| LookupTable::from(&ProjectivePoint::conditional_select(&x, &-x, r_sign)),
        xs,
        &r1_signs,
        LookupTable::default(),
    );
    let tables2 = static_zip_map(
        |x, r_sign| LookupTable::from(&ProjectivePoint::conditional_select(&x, &-x, r_sign)),
        &xs_beta,
        &r2_signs,
        LookupTable::default(),
    );

    let digits1 = static_map(
        |r| Radix16Decomposition::new(&r),
        &r1s_c,
        Radix16Decomposition::default(),
    );
    let digits2 = static_map(
        |r| Radix16Decomposition::new(&r),
        &r2s_c,
        Radix16Decomposition::default(),
    );

    let mut acc = ProjectivePoint::IDENTITY;
    for component in 0..N {
        acc += &tables1[component].select(digits1[component].0[32]);
        acc += &tables2[component].select(digits2[component].0[32]);
    }

    for i in (0..32).rev() {
        for _j in 0..4 {
            acc = acc.double();
        }

        for component in 0..N {
            acc += &tables1[component].select(digits1[component].0[i]);
            acc += &tables2[component].select(digits2[component].0[i]);
        }
    }
    acc
}

#[inline(always)]
fn mul(x: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
    lincomb_generic(&[*x], &[*k])
}

impl LinearCombination for ProjectivePoint {
    fn lincomb(
        x: &ProjectivePoint,
        k: &Scalar,
        y: &ProjectivePoint,
        l: &Scalar,
    ) -> ProjectivePoint {
        lincomb_generic(&[*x, *y], &[*k, *l])
    }
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: Scalar) -> ProjectivePoint {
        mul(&self, &other)
    }
}

impl Mul<&Scalar> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        mul(self, other)
    }
}

impl Mul<&Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        mul(&self, other)
    }
}

impl MulAssign<Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = mul(self, &rhs);
    }
}

impl MulAssign<&Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = mul(self, rhs);
    }
}

#[cfg(test)]
mod tests {
    use crate::arithmetic::{ProjectivePoint, Scalar};
    use elliptic_curve::{ops::LinearCombination, rand_core::OsRng, Field, Group};

    #[test]
    fn test_lincomb() {
        let x = ProjectivePoint::random(&mut OsRng);
        let y = ProjectivePoint::random(&mut OsRng);
        let k = Scalar::random(&mut OsRng);
        let l = Scalar::random(&mut OsRng);

        let reference = &x * &k + &y * &l;
        let test = ProjectivePoint::lincomb(&x, &k, &y, &l);
        assert_eq!(reference, test);
    }
}
