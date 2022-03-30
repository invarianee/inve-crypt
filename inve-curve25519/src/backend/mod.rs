#[cfg(not(any(
    feature = "u32_backend",
    feature = "u64_backend",
    feature = "fiat_u32_backend",
    feature = "fiat_u64_backend",
    feature = "simd_backend",
)))]
compile_error!(
    "no curve25519 backend cargo feature enabled! \
     please enable one of: u32_backend, u64_backend, fiat_u32_backend, fiat_u64_backend, simd_backend"
);

pub mod serial;

#[cfg(any(
    all(
        feature = "simd_backend",
        any(target_feature = "avx2", target_feature = "avx512ifma")
    ),
    all(feature = "nightly", rustdoc)
))]
#[cfg_attr(
    feature = "nightly",
    doc(cfg(any(all(
        feature = "simd_backend",
        any(target_feature = "avx2", target_feature = "avx512ifma")
    ))))
)]
pub mod vector;
