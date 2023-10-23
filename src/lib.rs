#![doc = include_str!("../README.md")]

mod k256;
pub use k256::{simd_keccak256, simd_keccak256_32b};
