#![allow(non_snake_case)]

use core::ops::{Mul, MulAssign};

use constants::{APLUS2_OVER_FOUR, MONTGOMERY_A, MONTGOMERY_A_NEG};
use edwards::{CompressedEdwardsY, EdwardsPoint};
use field::FieldElement;
use scalar::Scalar;

use traits::Identity;

use subtle::Choice;
use subtle::ConstantTimeEq;
use subtle::{ConditionallyNegatable, ConditionallySelectable};

use zeroize::Zeroize;

#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MontgomeryPoint(pub [u8; 32]);

impl ConstantTimeEq for MontgomeryPoint {
    fn ct_eq(&self, other: &MontgomeryPoint) -> Choice {
        let self_fe = FieldElement::from_bytes(&self.0);
        let other_fe = FieldElement::from_bytes(&other.0);

        self_fe.ct_eq(&other_fe)
    }
}

impl Default for MontgomeryPoint {
    fn default() -> MontgomeryPoint {
        MontgomeryPoint([0u8; 32])
    }
}

impl PartialEq for MontgomeryPoint {
    fn eq(&self, other: &MontgomeryPoint) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl Eq for MontgomeryPoint {}

impl Identity for MontgomeryPoint {
    fn identity() -> MontgomeryPoint {
        MontgomeryPoint([0u8; 32])
    }
}

impl Zeroize for MontgomeryPoint {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl MontgomeryPoint {
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; 32] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn to_edwards(&self, sign: u8) -> Option<EdwardsPoint> {
        let u = FieldElement::from_bytes(&self.0);

        if u == FieldElement::minus_one() {
            return None;
        }

        let one = FieldElement::one();

        let y = &(&u - &one) * &(&u + &one).invert();

        let mut y_bytes = y.to_bytes();
        y_bytes[31] ^= sign << 7;

        CompressedEdwardsY(y_bytes).decompress()
    }
}

#[allow(unused)]
pub(crate) fn elligator_encode(r_0: &FieldElement) -> MontgomeryPoint {
    let one = FieldElement::one();
    let d_1 = &one + &r_0.square2();

    let d = &MONTGOMERY_A_NEG * &(d_1.invert());

    let d_sq = &d.square();
    let au = &MONTGOMERY_A * &d;

    let inner = &(d_sq + &au) + &one;
    let eps = &d * &inner; /* eps = d^3 + Ad^2 + d */

    let (eps_is_sq, _eps) = FieldElement::sqrt_ratio_i(&eps, &one);

    let zero = FieldElement::zero();
    let Atemp = FieldElement::conditional_select(&MONTGOMERY_A, &zero, eps_is_sq); /* 0, or A if nonsquare*/
    let mut u = &d + &Atemp; /* d, or d+A if nonsquare */
    u.conditional_negate(!eps_is_sq); /* d, or -d-A if nonsquare */

    MontgomeryPoint(u.to_bytes())
}

#[derive(Copy, Clone, Debug)]
struct ProjectivePoint {
    pub U: FieldElement,
    pub W: FieldElement,
}

impl Identity for ProjectivePoint {
    fn identity() -> ProjectivePoint {
        ProjectivePoint {
            U: FieldElement::one(),
            W: FieldElement::zero(),
        }
    }
}

impl Default for ProjectivePoint {
    fn default() -> ProjectivePoint {
        ProjectivePoint::identity()
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(
        a: &ProjectivePoint,
        b: &ProjectivePoint,
        choice: Choice,
    ) -> ProjectivePoint {
        ProjectivePoint {
            U: FieldElement::conditional_select(&a.U, &b.U, choice),
            W: FieldElement::conditional_select(&a.W, &b.W, choice),
        }
    }
}

impl ProjectivePoint {
    pub fn to_affine(&self) -> MontgomeryPoint {
        let u = &self.U * &self.W.invert();
        MontgomeryPoint(u.to_bytes())
    }
}

fn differential_add_and_double(
    P: &mut ProjectivePoint,
    Q: &mut ProjectivePoint,
    affine_PmQ: &FieldElement,
) {
    let t0 = &P.U + &P.W;
    let t1 = &P.U - &P.W;
    let t2 = &Q.U + &Q.W;
    let t3 = &Q.U - &Q.W;

    let t4 = t0.square();
    let t5 = t1.square();

    let t6 = &t4 - &t5;

    let t7 = &t0 * &t3;
    let t8 = &t1 * &t2;

    let t9 = &t7 + &t8;
    let t10 = &t7 - &t8;

    let t11 = t9.square();
    let t12 = t10.square();

    let t13 = &APLUS2_OVER_FOUR * &t6;

    let t14 = &t4 * &t5;
    let t15 = &t13 + &t5;

    let t16 = &t6 * &t15;

    let t17 = affine_PmQ * &t12;
    let t18 = t11;

    P.U = t14;
    P.W = t16;
    Q.U = t18;
    Q.W = t17;
}

define_mul_assign_variants!(LHS = MontgomeryPoint, RHS = Scalar);

define_mul_variants!(
    LHS = MontgomeryPoint,
    RHS = Scalar,
    Output = MontgomeryPoint
);
define_mul_variants!(
    LHS = Scalar,
    RHS = MontgomeryPoint,
    Output = MontgomeryPoint
);

impl<'a, 'b> Mul<&'b Scalar> for &'a MontgomeryPoint {
    type Output = MontgomeryPoint;

    fn mul(self, scalar: &'b Scalar) -> MontgomeryPoint {
        let affine_u = FieldElement::from_bytes(&self.0);
        let mut x0 = ProjectivePoint::identity();
        let mut x1 = ProjectivePoint {
            U: affine_u,
            W: FieldElement::one(),
        };

        let bits: [i8; 256] = scalar.bits();

        for i in (0..255).rev() {
            let choice: u8 = (bits[i + 1] ^ bits[i]) as u8;

            debug_assert!(choice == 0 || choice == 1);

            ProjectivePoint::conditional_swap(&mut x0, &mut x1, choice.into());
            differential_add_and_double(&mut x0, &mut x1, &affine_u);
        }
        ProjectivePoint::conditional_swap(&mut x0, &mut x1, Choice::from(bits[0] as u8));

        x0.to_affine()
    }
}

impl<'b> MulAssign<&'b Scalar> for MontgomeryPoint {
    fn mul_assign(&mut self, scalar: &'b Scalar) {
        *self = (self as &MontgomeryPoint) * scalar;
    }
}

impl<'a, 'b> Mul<&'b MontgomeryPoint> for &'a Scalar {
    type Output = MontgomeryPoint;

    fn mul(self, point: &'b MontgomeryPoint) -> MontgomeryPoint {
        point * self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use constants;
    use core::convert::TryInto;

    use rand_core::OsRng;

    #[test]
    fn identity_in_different_coordinates() {
        let id_projective = ProjectivePoint::identity();
        let id_montgomery = id_projective.to_affine();

        assert!(id_montgomery == MontgomeryPoint::identity());
    }

    #[test]
    fn identity_in_different_models() {
        assert!(EdwardsPoint::identity().to_montgomery() == MontgomeryPoint::identity());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_bincode_basepoint_roundtrip() {
        use bincode;

        let encoded = bincode::serialize(&constants::X25519_BASEPOINT).unwrap();
        let decoded: MontgomeryPoint = bincode::deserialize(&encoded).unwrap();

        assert_eq!(encoded.len(), 32);
        assert_eq!(decoded, constants::X25519_BASEPOINT);

        let raw_bytes = constants::X25519_BASEPOINT.as_bytes();
        let bp: MontgomeryPoint = bincode::deserialize(raw_bytes).unwrap();
        assert_eq!(bp, constants::X25519_BASEPOINT);
    }

    #[test]
    fn basepoint_montgomery_to_edwards() {
        assert_eq!(
            constants::ED25519_BASEPOINT_POINT,
            constants::X25519_BASEPOINT.to_edwards(0).unwrap()
        );
        assert_eq!(
            -constants::ED25519_BASEPOINT_POINT,
            constants::X25519_BASEPOINT.to_edwards(1).unwrap()
        );
    }

    #[test]
    fn basepoint_edwards_to_montgomery() {
        assert_eq!(
            constants::ED25519_BASEPOINT_POINT.to_montgomery(),
            constants::X25519_BASEPOINT
        );
    }

    #[test]
    fn montgomery_to_edwards_rejects_twist() {
        let one = FieldElement::one();

        let two = MontgomeryPoint((&one + &one).to_bytes());

        assert!(two.to_edwards(0).is_none());

        let minus_one = MontgomeryPoint((-&one).to_bytes());

        assert!(minus_one.to_edwards(0).is_none());
    }

    #[test]
    fn eq_defined_mod_p() {
        let mut u18_bytes = [0u8; 32];
        u18_bytes[0] = 18;
        let u18 = MontgomeryPoint(u18_bytes);
        let u18_unred = MontgomeryPoint([255; 32]);

        assert_eq!(u18, u18_unred);
    }

    #[test]
    fn montgomery_ladder_matches_edwards_scalarmult() {
        let mut csprng: OsRng = OsRng;

        let s: Scalar = Scalar::random(&mut csprng);
        let p_edwards: EdwardsPoint = &constants::ED25519_BASEPOINT_TABLE * &s;
        let p_montgomery: MontgomeryPoint = p_edwards.to_montgomery();

        let expected = s * p_edwards;
        let result = s * p_montgomery;

        assert_eq!(result, expected.to_montgomery())
    }

    const ELLIGATOR_CORRECT_OUTPUT: [u8; 32] = [
        0x5f, 0x35, 0x20, 0x00, 0x1c, 0x6c, 0x99, 0x36, 0xa3, 0x12, 0x06, 0xaf, 0xe7, 0xc7, 0xac,
        0x22, 0x4e, 0x88, 0x61, 0x61, 0x9b, 0xf9, 0x88, 0x72, 0x44, 0x49, 0x15, 0x89, 0x9d, 0x95,
        0xf4, 0x6e,
    ];

    #[test]
    #[cfg(feature = "std")]
    fn montgomery_elligator_correct() {
        let bytes: std::vec::Vec<u8> = (0u8..32u8).collect();
        let bits_in: [u8; 32] = (&bytes[..]).try_into().expect("Range invariant broken");

        let fe = FieldElement::from_bytes(&bits_in);
        let eg = elligator_encode(&fe);
        assert_eq!(eg.to_bytes(), ELLIGATOR_CORRECT_OUTPUT);
    }

    #[test]
    fn montgomery_elligator_zero_zero() {
        let zero = [0u8; 32];
        let fe = FieldElement::from_bytes(&zero);
        let eg = elligator_encode(&fe);
        assert_eq!(eg.to_bytes(), zero);
    }
}
