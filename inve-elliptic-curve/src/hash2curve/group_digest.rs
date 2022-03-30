use super::{hash_to_field, ExpandMsg, FromOkm, MapToCurve};
use crate::{ProjectiveArithmetic, ProjectivePoint, Result};
use group::cofactor::CofactorGroup;

pub trait GroupDigest: ProjectiveArithmetic
where
    ProjectivePoint<Self>: CofactorGroup,
{
    type FieldElement: FromOkm + MapToCurve<Output = ProjectivePoint<Self>> + Default + Copy;

    fn hash_from_bytes<'a, X: ExpandMsg<'a>>(
        msgs: &[&[u8]],
        dst: &'a [u8],
    ) -> Result<ProjectivePoint<Self>> {
        let mut u = [Self::FieldElement::default(), Self::FieldElement::default()];
        hash_to_field::<X, _>(msgs, dst, &mut u)?;
        let q0 = u[0].map_to_curve();
        let q1 = u[1].map_to_curve();
        Ok(q0.clear_cofactor().into() + q1.clear_cofactor())
    }

    fn encode_from_bytes<'a, X: ExpandMsg<'a>>(
        msgs: &[&[u8]],
        dst: &'a [u8],
    ) -> Result<ProjectivePoint<Self>> {
        let mut u = [Self::FieldElement::default()];
        hash_to_field::<X, _>(msgs, dst, &mut u)?;
        let q0 = u[0].map_to_curve();
        Ok(q0.clear_cofactor().into())
    }

    fn hash_to_scalar<'a, X: ExpandMsg<'a>>(msgs: &[&[u8]], dst: &'a [u8]) -> Result<Self::Scalar>
    where
        Self::Scalar: FromOkm,
    {
        let mut u = [Self::Scalar::default()];
        hash_to_field::<X, _>(msgs, dst, &mut u)?;
        Ok(u[0])
    }
}
