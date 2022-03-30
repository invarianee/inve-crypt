use crate::{Curve, FieldBytes};
use subtle::{Choice, CtOption};

pub trait AffineXCoordinate<C: Curve> {
    fn x(&self) -> FieldBytes<C>;
}

pub trait DecompressPoint<C: Curve>: Sized {
    fn decompress(x: &FieldBytes<C>, y_is_odd: Choice) -> CtOption<Self>;
}

pub trait DecompactPoint<C: Curve>: Sized {
    fn decompact(x: &FieldBytes<C>) -> CtOption<Self>;
}

pub trait PointCompression {
    const COMPRESS_POINTS: bool;
}

pub trait PointCompaction {
    const COMPACT_POINTS: bool;
}
