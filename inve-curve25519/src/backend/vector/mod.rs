#![cfg_attr(
    feature = "nightly",
    doc(include = "../../../docs/parallel-formulas.md")
)]

#[cfg(not(any(target_feature = "avx2", target_feature = "avx512ifma", rustdoc)))]
compile_error!("simd_backend selected without target_feature=+avx2 or +avx512ifma");

#[cfg(any(
    all(target_feature = "avx2", not(target_feature = "avx512ifma")),
    rustdoc
))]
#[doc(cfg(all(target_feature = "avx2", not(target_feature = "avx512ifma"))))]
pub mod avx2;
#[cfg(any(
    all(target_feature = "avx2", not(target_feature = "avx512ifma")),
    rustdoc
))]
pub(crate) use self::avx2::{
    constants::BASEPOINT_ODD_LOOKUP_TABLE, edwards::CachedPoint, edwards::ExtendedPoint,
};

#[cfg(any(target_feature = "avx512ifma", rustdoc))]
#[doc(cfg(target_feature = "avx512ifma"))]
pub mod ifma;
#[cfg(target_feature = "avx512ifma")]
pub(crate) use self::ifma::{
    constants::BASEPOINT_ODD_LOOKUP_TABLE, edwards::CachedPoint, edwards::ExtendedPoint,
};

pub mod scalar_mul;
