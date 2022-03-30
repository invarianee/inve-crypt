use ff::Field;
use subtle::Choice;

pub struct OsswuMapParams<F>
where
    F: Field,
{
    pub c1: [u64; 4],
    pub c2: F,
    pub map_a: F,
    pub map_b: F,
    pub z: F,
}

pub trait Sgn0 {
    fn sgn0(&self) -> Choice;
}

pub trait OsswuMap: Field + Sgn0 {
    const PARAMS: OsswuMapParams<Self>;

    fn osswu(&self) -> (Self, Self) {
        let tv1 = self.square();
        let tv3 = Self::PARAMS.z * tv1;
        let mut tv2 = tv3.square();
        let mut xd = tv2 + tv3;
        let x1n = Self::PARAMS.map_b * (xd + Self::one());
        xd *= -Self::PARAMS.map_a;

        let tv = Self::PARAMS.z * Self::PARAMS.map_a;
        xd.conditional_assign(&tv, xd.is_zero());

        tv2 = xd.square();
        let gxd = tv2 * xd;
        tv2 *= Self::PARAMS.map_a;

        let mut gx1 = x1n * (tv2 + x1n.square());
        tv2 = gxd * Self::PARAMS.map_b;
        gx1 += tv2;

        let mut tv4 = gxd.square();
        tv2 = gx1 * gxd;
        tv4 *= tv2;

        let y1 = tv4.pow_vartime(&Self::PARAMS.c1) * tv2;
        let x2n = tv3 * x1n;

        let y2 = y1 * Self::PARAMS.c2 * tv1 * self;

        tv2 = y1.square() * gxd;

        let e2 = tv2.ct_eq(&gx1);

        let mut x = Self::conditional_select(&x2n, &x1n, e2);
        x *= xd.invert().unwrap();

        let mut y = Self::conditional_select(&y2, &y1, e2);

        y.conditional_assign(&-y, self.sgn0() ^ y.sgn0());
        (x, y)
    }
}
