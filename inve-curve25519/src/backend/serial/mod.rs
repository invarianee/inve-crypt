#[cfg(not(any(
    feature = "u32_backend",
    feature = "u64_backend",
    feature = "fiat_u32_backend",
    feature = "fiat_u64_backend"
)))]
compile_error!(
    "no curve25519 backend cargo feature enabled! \
     please enable one of: u32_backend, u64_backend, fiat_u32_backend, fiat_u64_backend"
);

#[cfg(feature = "u32_backend")]
pub mod u32;

#[cfg(feature = "u64_backend")]
pub mod u64;

#[cfg(feature = "fiat_u32_backend")]
pub mod fiat_u32;

#[cfg(feature = "fiat_u64_backend")]
pub mod fiat_u64;

pub mod curve_models;

#[cfg(not(all(
    feature = "simd_backend",
    any(target_feature = "avx2", target_feature = "avx512ifma")
)))]
pub mod scalar_mul;
