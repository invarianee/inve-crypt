use core::ops::{AddAssign, Mul};
use ff::Field;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

pub struct IsogenyCoefficients<F: Field + AddAssign + Mul<Output = F>> {
    pub xnum: &'static [F],
    pub xden: &'static [F],
    pub ynum: &'static [F],
    pub yden: &'static [F],
}

pub trait Isogeny: Field + AddAssign + Mul<Output = Self> {
    type Degree: ArrayLength<Self>;
    const COEFFICIENTS: IsogenyCoefficients<Self>;

    fn isogeny(x: Self, y: Self) -> (Self, Self) {
        let mut xs = GenericArray::<Self, Self::Degree>::default();
        xs[0] = Self::one();
        xs[1] = x;
        xs[2] = x.square();
        for i in 3..Self::Degree::to_usize() {
            xs[i] = xs[i - 1] * x;
        }
        let x_num = Self::compute_iso(&xs, Self::COEFFICIENTS.xnum);
        let x_den = Self::compute_iso(&xs, Self::COEFFICIENTS.xden)
            .invert()
            .unwrap();
        let y_num = Self::compute_iso(&xs, Self::COEFFICIENTS.ynum) * y;
        let y_den = Self::compute_iso(&xs, Self::COEFFICIENTS.yden)
            .invert()
            .unwrap();

        (x_num * x_den, y_num * y_den)
    }

    fn compute_iso(xxs: &[Self], k: &[Self]) -> Self {
        let mut xx = Self::zero();
        for (xi, ki) in xxs.iter().zip(k.iter()) {
            xx += *xi * ki;
        }
        xx
    }
}
