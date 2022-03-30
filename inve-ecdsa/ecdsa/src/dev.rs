pub struct TestVector {
    pub d: &'static [u8],

    pub q_x: &'static [u8],

    pub q_y: &'static [u8],

    pub k: &'static [u8],

    pub m: &'static [u8],

    pub r: &'static [u8],

    pub s: &'static [u8],
}

#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! new_signing_test {
    ($curve:path, $vectors:expr) => {
        use $crate::{
            elliptic_curve::{
                bigint::Encoding, generic_array::GenericArray, group::ff::PrimeField, Curve,
                ProjectiveArithmetic, Scalar,
            },
            hazmat::SignPrimitive,
        };

        fn decode_scalar(bytes: &[u8]) -> Option<Scalar<$curve>> {
            if bytes.len() == <$curve as Curve>::UInt::BYTE_SIZE {
                Scalar::<$curve>::from_repr(GenericArray::clone_from_slice(bytes)).into()
            } else {
                None
            }
        }

        #[test]
        fn ecdsa_signing() {
            for vector in $vectors {
                let d = decode_scalar(vector.d).expect("invalid vector.d");
                let k = decode_scalar(vector.k).expect("invalid vector.m");
                let z = decode_scalar(vector.m).expect("invalid vector.z");
                let sig = d.try_sign_prehashed(k, z).expect("ECDSA sign failed").0;

                assert_eq!(vector.r, sig.r().to_bytes().as_slice());
                assert_eq!(vector.s, sig.s().to_bytes().as_slice());
            }
        }
    };
}

#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! new_verification_test {
    ($curve:path, $vectors:expr) => {
        use $crate::{
            elliptic_curve::{
                generic_array::GenericArray,
                group::ff::PrimeField,
                sec1::{EncodedPoint, FromEncodedPoint},
                AffinePoint, ProjectiveArithmetic, Scalar,
            },
            hazmat::VerifyPrimitive,
            Signature,
        };

        #[test]
        fn ecdsa_verify_success() {
            for vector in $vectors {
                let q_encoded = EncodedPoint::<$curve>::from_affine_coordinates(
                    GenericArray::from_slice(vector.q_x),
                    GenericArray::from_slice(vector.q_y),
                    false,
                );

                let q = AffinePoint::<$curve>::from_encoded_point(&q_encoded).unwrap();

                let maybe_z = Scalar::<$curve>::from_repr(GenericArray::clone_from_slice(vector.m));
                assert!(bool::from(maybe_z.is_some()), "invalid vector.m");
                let z = maybe_z.unwrap();

                let sig = Signature::from_scalars(
                    GenericArray::clone_from_slice(vector.r),
                    GenericArray::clone_from_slice(vector.s),
                )
                .unwrap();

                let result = q.verify_prehashed(z, &sig);
                assert!(result.is_ok());
            }
        }

        #[test]
        fn ecdsa_verify_invalid_s() {
            for vector in $vectors {
                let q_encoded = EncodedPoint::<$curve>::from_affine_coordinates(
                    GenericArray::from_slice(vector.q_x),
                    GenericArray::from_slice(vector.q_y),
                    false,
                );

                let q = AffinePoint::<$curve>::from_encoded_point(&q_encoded).unwrap();

                let maybe_z = Scalar::<$curve>::from_repr(GenericArray::clone_from_slice(vector.m));
                assert!(bool::from(maybe_z.is_some()), "invalid vector.m");
                let z = maybe_z.unwrap();

                let mut s_tweaked = GenericArray::clone_from_slice(vector.s);
                s_tweaked[0] ^= 1;

                let sig =
                    Signature::from_scalars(GenericArray::clone_from_slice(vector.r), s_tweaked)
                        .unwrap();

                let result = q.verify_prehashed(z, &sig);
                assert!(result.is_err());
            }
        }
    };
}

#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! new_wycheproof_test {
    ($name:ident, $test_name: expr, $curve:path) => {
        use $crate::{elliptic_curve::sec1::EncodedPoint, signature::Verifier, Signature};

        #[test]
        fn $name() {
            use blobby::Blob5Iterator;
            use elliptic_curve::{bigint::Encoding as _, generic_array::typenum::Unsigned};

            fn element_from_padded_slice<C: elliptic_curve::Curve>(
                data: &[u8],
            ) -> elliptic_curve::FieldBytes<C> {
                let point_len = C::UInt::BYTE_SIZE;
                if data.len() >= point_len {
                    let offset = data.len() - point_len;
                    for v in data.iter().take(offset) {
                        assert_eq!(*v, 0, "EcdsaVerifier: point too large");
                    }
                    elliptic_curve::FieldBytes::<C>::clone_from_slice(&data[offset..])
                } else {
                    let iter = core::iter::repeat(0)
                        .take(point_len - data.len())
                        .chain(data.iter().cloned());
                    elliptic_curve::FieldBytes::<C>::from_exact_iter(iter).unwrap()
                }
            }

            fn run_test(
                wx: &[u8],
                wy: &[u8],
                msg: &[u8],
                sig: &[u8],
                pass: bool,
            ) -> Option<&'static str> {
                let x = element_from_padded_slice::<$curve>(wx);
                let y = element_from_padded_slice::<$curve>(wy);
                let q_encoded = EncodedPoint::<$curve>::from_affine_coordinates(
                    &x, &y, /* compress= */ false,
                );
                let verifying_key =
                    $crate::VerifyingKey::<$curve>::from_encoded_point(&q_encoded).unwrap();

                let sig = match Signature::from_der(sig) {
                    Ok(s) => s,
                    Err(_) if !pass => return None,
                    Err(_) => return Some("failed to parse signature ASN.1"),
                };

                match verifying_key.verify(msg, &sig) {
                    Ok(_) if pass => None,
                    Ok(_) => Some("signature verify unexpectedly succeeded"),
                    Err(_) if !pass => None,
                    Err(_) => Some("signature verify failed"),
                }
            }

            let data = include_bytes!(concat!("test_vectors/data/", $test_name, ".blb"));

            for (i, row) in Blob5Iterator::new(data).unwrap().enumerate() {
                let [wx, wy, msg, sig, status] = row.unwrap();
                let pass = match status[0] {
                    0 => false,
                    1 => true,
                    _ => panic!("invalid value for pass flag"),
                };
                if let Some(desc) = run_test(wx, wy, msg, sig, pass) {
                    panic!(
                        "\n\
                                 Failed test №{}: {}\n\
                                 wx:\t{:?}\n\
                                 wy:\t{:?}\n\
                                 msg:\t{:?}\n\
                                 sig:\t{:?}\n\
                                 pass:\t{}\n",
                        i, desc, wx, wy, msg, sig, pass,
                    );
                }
            }
        }
    };
}
