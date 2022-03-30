pub trait MapToCurve {
    type Output;

    fn map_to_curve(&self) -> Self::Output;
}
