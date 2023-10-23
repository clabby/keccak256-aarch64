# `keccak256-aarch64`

> **Warning**
> This crate was forked from real cryptographers ([Goldilocks by Remco Bloeman](https://github.com/recmo/goldilocks/tree/main)), by not a real cryptographer. Do not
> use this keccak256 implementation for anything serious.

This crate provides an aarch64-specific implementation of the `keccak256` hash function that allows for computing the hashes of two 32 byte inputs
in parallel using the SIMD instructions available on aarch64.
