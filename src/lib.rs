#![doc = include_str!("../README.md")]
#![cfg(all(target_arch = "aarch64", target_feature = "sha3"))]

mod k256;
pub use k256::{
    simd_keccak256_32b_double, simd_keccak256_64b_double, simd_keccak256_double,
    simd_keccak256_single,
};
