extern crate proc_macro;

use proc_macro2::TokenStream;
use quote::quote;
use synstructure::{decl_derive, AddBounds};

fn derive_signer(mut s: synstructure::Structure) -> TokenStream {
    s.add_bounds(AddBounds::None);
    s.gen_impl(quote! {
        gen impl<S> signature::Signer<S> for @Self
        where
            S: signature::PrehashSignature,
            Self: signature::DigestSigner<S::Digest, S>
        {
            fn try_sign(&self, msg: &[u8]) -> Result<S, signature::Error> {
                self.try_sign_digest(S::Digest::new_with_prefix(msg))
            }
        }
    })
}

decl_derive! {
    [Signer] =>
    derive_signer
}

fn derive_verifier(mut s: synstructure::Structure) -> TokenStream {
    s.add_bounds(AddBounds::None);
    s.gen_impl(quote! {
        gen impl<S> signature::Verifier<S> for @Self
        where
            S: signature::PrehashSignature,
            Self: signature::DigestVerifier<S::Digest, S>
        {
            fn verify(&self, msg: &[u8], signature: &S) -> Result<(), signature::Error> {
                self.verify_digest(S::Digest::new_with_prefix(msg), signature)
            }
        }
    })
}

decl_derive! {
    [Verifier] =>
    derive_verifier
}

#[cfg(test)]
mod tests {
    use super::*;
    use synstructure::test_derive;

    #[test]
    fn signer() {
        test_derive! {
            derive_signer {
                struct MySigner<C: EllipticCurve> {
                    scalar: Scalar<C::ScalarSize>
                }
            }
            expands to {
                #[allow(non_upper_case_globals)]
                const _DERIVE_signature_Signer_S_FOR_MySigner: () = {
                    impl<S, C: EllipticCurve> signature::Signer<S> for MySigner<C>
                    where
                        S: signature::PrehashSignature,
                        Self: signature::DigestSigner<S::Digest, S>
                    {
                        fn try_sign(&self, msg: &[u8]) -> Result <S, signature::Error> {
                            self.try_sign_digest(S::Digest::new_with_prefix(msg))
                        }
                    }
                };
            }
            no_build
        }
    }

    #[test]
    fn verifier() {
        test_derive! {
            derive_verifier {
                struct MyVerifier<C: EllipticCurve> {
                    point: UncompressedPoint<C>
                }
            }
            expands to {
                #[allow(non_upper_case_globals)]
                const _DERIVE_signature_Verifier_S_FOR_MyVerifier: () = {
                    impl<S, C: EllipticCurve> signature::Verifier<S> for MyVerifier<C>
                    where
                        S: signature::PrehashSignature,
                        Self: signature::DigestVerifier<S::Digest, S>
                    {
                        fn verify(&self, msg: &[u8], signature: &S) -> Result<(), signature::Error> {
                            self.verify_digest(S::Digest::new_with_prefix(msg), signature)
                        }
                    }
                };
            }
            no_build
        }
    }
}
