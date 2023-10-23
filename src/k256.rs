//! Contains a (restricted) Keccak256 implementation for ARMv8-A.

/// Round constants for the Keccak-f[1600] permutation.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Double keccak256 on ARMv8-A. Input size restricted to the range of [0, 1080] bits.
///
/// Credits to @recmo for the reference K12 implementation in [Goldilocks](https://github.com/recmo/goldilocks/blob/main/pcs/src/k12/aarch64.rs).
///
/// Keccak256 bitrate = `1088`, capacity = `512`
#[allow(asm_sub_register)]
#[inline(always)]
pub fn simd_keccak256_double<const B: usize>(input: &[u8], output: &mut [u8]) {
    assert!(input.len() <= 270 && input.len() == B * 2 && output.len() == 64);

    // TODO: Because the inputs are equal length, we can probably avoid padding both sides and just
    // pad once with dup.2d (?)
    let mut input_padded = [0u8; 272];
    pad_keccak_input::<B, 272>(&mut input_padded, input, 0, 0);
    pad_keccak_input::<B, 272>(&mut input_padded, input, 136, B);

    crate::keccak_256_permutation!(
        input_padded,
        output,
        RC,
        setup = "
            // Read first block into v0-v16 lower 64-bit.
            ld4.d {{ v0- v3}}[0], [{input}], #32
            ld4.d {{ v4- v7}}[0], [{input}], #32
            ld4.d {{ v8-v11}}[0], [{input}], #32
            ld4.d {{v12-v15}}[0], [{input}], #32
            ld1.d {{v16}}[0],     [{input}], #8

            // Read second block into v0-v16 upper 64-bit.
            ld4.d {{ v0- v3}}[1], [{input}], #32
            ld4.d {{ v4- v7}}[1], [{input}], #32
            ld4.d {{ v8-v11}}[1], [{input}], #32
            ld4.d {{v12-v15}}[1], [{input}], #32
            ld1.d {{v16}}[1],     [{input}], #8

            // Zero the capacity bits (`512` capacity bits in keccak256, so the final `8` registers - `8 * 64 = 512`)
            dup.2d v17, xzr
            dup.2d v18, xzr
            dup.2d v19, xzr
            dup.2d v20, xzr
            dup.2d v21, xzr
            dup.2d v22, xzr
            dup.2d v23, xzr
            dup.2d v24, xzr
        ",
        teardown = "
            // Write output (first 256 bits of state)
            st4.d {{ v0- v3}}[0], [{output}], #32
            st4.d {{ v0- v3}}[1], [{output}], #32

        "
    );
}

/// Single keccak256 on ARMv8-A. Input size restricted to the range of [0, 1080] bits.
///
/// Credits to @recmo for the reference K12 implementation in [Goldilocks](https://github.com/recmo/goldilocks/blob/main/pcs/src/k12/aarch64.rs).
///
/// Keccak256 bitrate = `1088`, capacity = `512`
#[allow(asm_sub_register)]
#[inline(always)]
pub fn simd_keccak256_single<const B: usize>(input: &[u8], output: &mut [u8]) {
    assert!(input.len() <= 135 && input.len() == B && output.len() == 32);

    let mut input_padded = [0u8; 136];
    pad_keccak_input::<B, 136>(&mut input_padded, input, 0, 0);

    crate::keccak_256_permutation!(
        input_padded,
        output,
        RC,
        setup = "
            // Read first block into v0-v16 lower 64-bit.
            ld4.d {{ v0- v3}}[0], [{input}], #32
            ld4.d {{ v4- v7}}[0], [{input}], #32
            ld4.d {{ v8-v11}}[0], [{input}], #32
            ld4.d {{v12-v15}}[0], [{input}], #32
            ld1.d {{v16}}[0],     [{input}], #8

            // Zero the capacity bits (`512` capacity bits in keccak256, so the final `8` registers - `8 * 64 = 512`)
            dup.2d v17, xzr
            dup.2d v18, xzr
            dup.2d v19, xzr
            dup.2d v20, xzr
            dup.2d v21, xzr
            dup.2d v22, xzr
            dup.2d v23, xzr
            dup.2d v24, xzr
        ",
        teardown = "
            // Write output (first 256 bits of state)
            st4.d {{ v0- v3}}[0], [{output}], #32
        "
    );
}

/// Double keccak256 on ARMv8-A. Input size restricted to 64 bytes, 32 bytes on either half of the
/// slice.
///
/// Credits to @recmo for the reference K12 implementation in [Goldilocks](https://github.com/recmo/goldilocks/blob/main/pcs/src/k12/aarch64.rs).
///
/// Keccak256 bitrate = `1088`, capacity = `512`
#[allow(asm_sub_register)]
pub fn simd_keccak256_32b_double(input: &[u8], output: &mut [u8]) {
    assert_eq!(input.len(), 64);
    assert_eq!(output.len(), 64);

    crate::keccak_256_permutation!(
        input,
        output,
        RC,
        setup = "
            // Read first block into v0-v3 lower 64-bit.
            ld4.d {{ v0- v3}}[0], [{input}], #32

            // Read second block into v0-v3 upper 64-bit.
            ld4.d {{ v0- v3}}[1], [{input}], #32

            // Set the starting padding bit in v4
            movz {input}, #0x01
            dup.2d v4, {input}

            // Zero padding
            dup.2d v5, xzr
            dup.2d v6, xzr
            dup.2d v7, xzr
            dup.2d v8, xzr
            dup.2d v9, xzr
            dup.2d v10, xzr
            dup.2d v11, xzr
            dup.2d v12, xzr
            dup.2d v13, xzr
            dup.2d v14, xzr
            dup.2d v15, xzr

            // Add final padding bit `1088 - 256 = 832 bits`, so `13` registers (`13 * 64 = 832 bits`)
            // worth of padding is necessary.
            movz {input}, #0x8000, lsl #48
            dup.2d v16, {input}

            // Zero the capacity bits (`512` capacity bits in keccak256, so the final `8` registers - `8 * 64 = 512`)
            dup.2d v17, xzr
            dup.2d v18, xzr
            dup.2d v19, xzr
            dup.2d v20, xzr
            dup.2d v21, xzr
            dup.2d v22, xzr
            dup.2d v23, xzr
            dup.2d v24, xzr
        ",
        teardown = "
            // Write output (first 256 bits of state)
            st4.d {{ v0- v3}}[0], [{output}], #32
            st4.d {{ v0- v3}}[1], [{output}], #32
        "
    );
}

/// Single keccak256 on ARMv8-A. Input size restricted to 32 bytes.
///
/// Credits to @recmo for the reference K12 implementation in [Goldilocks](https://github.com/recmo/goldilocks/blob/main/pcs/src/k12/aarch64.rs).
///
/// Keccak256 bitrate = `1088`, capacity = `512`
#[allow(asm_sub_register)]
pub fn simd_keccak256_32b_single(input: &[u8], output: &mut [u8]) {
    assert!(input.len() == 32 && output.len() == 32);

    crate::keccak_256_permutation!(
        input,
        output,
        RC,
        setup = "
            // Read first block into v0-v3 lower 64-bit.
            ld4.d {{ v0- v3}}[0], [{input}], #32

            // Set the starting padding bit in v4
            movz {input}, #0x01
            dup.2d v4, {input}

            // Zero padding
            dup.2d v5, xzr
            dup.2d v6, xzr
            dup.2d v7, xzr
            dup.2d v8, xzr
            dup.2d v9, xzr
            dup.2d v10, xzr
            dup.2d v11, xzr
            dup.2d v12, xzr
            dup.2d v13, xzr
            dup.2d v14, xzr
            dup.2d v15, xzr

            // Add final padding bit `1088 - 256 = 832 bits`, so `13` registers (`13 * 64 = 832 bits`)
            // worth of padding is necessary.
            movz {input}, #0x8000, lsl #48
            dup.2d v16, {input}

            // Zero the capacity bits (`512` capacity bits in keccak256, so the final `8` registers - `8 * 64 = 512`)
            dup.2d v17, xzr
            dup.2d v18, xzr
            dup.2d v19, xzr
            dup.2d v20, xzr
            dup.2d v21, xzr
            dup.2d v22, xzr
            dup.2d v23, xzr
            dup.2d v24, xzr
        ",
        teardown = "
            // Write output (first 256 bits of state)
            st4.d {{ v0- v3}}[0], [{output}], #32
        "
    );
}

/// Double keccak256 on ARMv8-A. Input size restricted to 128 bytes, 64 bytes on either half of the
/// slice.
///
/// Credits to @recmo for the reference K12 implementation in [Goldilocks](https://github.com/recmo/goldilocks/blob/main/pcs/src/k12/aarch64.rs).
///
/// Keccak256 bitrate = `1088`, capacity = `512`
#[allow(asm_sub_register)]
pub fn simd_keccak256_64b_double(input: &[u8], output: &mut [u8]) {
    assert_eq!(input.len(), 128);
    assert_eq!(output.len(), 64);

    crate::keccak_256_permutation!(
        input,
        output,
        RC,
        setup = "
            // Read first block into v0-v7 lower 64-bit.
            ld4.d {{ v0- v3}}[0], [{input}], #32
            ld4.d {{ v4- v7}}[0], [{input}], #32

            // Read second block into v0-v7 upper 64-bit.
            ld4.d {{ v0- v3}}[1], [{input}], #32
            ld4.d {{ v4- v7}}[1], [{input}], #32

            // Set the starting padding bit in v8
            movz {input}, #0x01
            dup.2d v8, {input}

            // Zero padding
            dup.2d v9, xzr
            dup.2d v10, xzr
            dup.2d v11, xzr
            dup.2d v12, xzr
            dup.2d v13, xzr
            dup.2d v14, xzr
            dup.2d v15, xzr

            // Add final padding bit `1088 - 256 = 832 bits`, so `13` registers (`13 * 64 = 832 bits`)
            // worth of padding is necessary.
            movz {input}, #0x8000, lsl #48
            dup.2d v16, {input}

            // Zero the capacity bits (`512` capacity bits in keccak256, so the final `8` registers - `8 * 64 = 512`)
            dup.2d v17, xzr
            dup.2d v18, xzr
            dup.2d v19, xzr
            dup.2d v20, xzr
            dup.2d v21, xzr
            dup.2d v22, xzr
            dup.2d v23, xzr
            dup.2d v24, xzr
        ",
        teardown = "
            // Write output (first 256 bits of state)
            st4.d {{ v0- v3}}[0], [{output}], #32
            st4.d {{ v0- v3}}[1], [{output}], #32
        "
    );
}

/// Single keccak256 on ARMv8-A. Input size restricted to 64 bytes.
///
/// Credits to @recmo for the reference K12 implementation in [Goldilocks](https://github.com/recmo/goldilocks/blob/main/pcs/src/k12/aarch64.rs).
///
/// Keccak256 bitrate = `1088`, capacity = `512`
#[allow(asm_sub_register)]
pub fn simd_keccak256_64b_single(input: &[u8], output: &mut [u8]) {
    assert!(input.len() == 64 && output.len() == 32);

    crate::keccak_256_permutation!(
        input,
        output,
        RC,
        setup = "
            // Read first block into v0-v7 lower 64-bit.
            ld4.d {{ v0- v3}}[0], [{input}], #32
            ld4.d {{ v4- v7}}[0], [{input}], #32

            // Set the starting padding bit in v8
            movz {input}, #0x01
            dup.2d v8, {input}

            // Zero padding
            dup.2d v9, xzr
            dup.2d v10, xzr
            dup.2d v11, xzr
            dup.2d v12, xzr
            dup.2d v13, xzr
            dup.2d v14, xzr
            dup.2d v15, xzr

            // Add final padding bit `1088 - 256 = 832 bits`, so `13` registers (`13 * 64 = 832 bits`)
            // worth of padding is necessary.
            movz {input}, #0x8000, lsl #48
            dup.2d v16, {input}

            // Zero the capacity bits (`512` capacity bits in keccak256, so the final `8` registers - `8 * 64 = 512`)
            dup.2d v17, xzr
            dup.2d v18, xzr
            dup.2d v19, xzr
            dup.2d v20, xzr
            dup.2d v21, xzr
            dup.2d v22, xzr
            dup.2d v23, xzr
            dup.2d v24, xzr
        ",
        teardown = "
            // Write output (first 256 bits of state)
            st4.d {{ v0- v3}}[0], [{output}], #32
        "
    );
}

#[macro_export]
macro_rules! keccak_256_permutation {
    ($input:ident, $output:ident, $rc:ident, setup = $setup:literal, teardown = $teardown:literal) => {
        unsafe {
            core::arch::asm!(
                $setup,
                include_str!("keccak_f1600.asm"),
                $teardown,
                input = inout(reg) $input.as_ptr() => _,
                output = inout(reg) $output.as_mut_ptr() => _,
                loop = inout(reg) 24 => _,
                rc = inout(reg) $rc.as_ptr() => _,
                out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _,
                out("v5") _, out("v6") _, out("v7") _, out("v8") _, out("v9") _,
                out("v10") _, out("v11") _, out("v12") _, out("v13") _, out("v14") _,
                out("v15") _, out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                out("v20") _, out("v21") _, out("v22") _, out("v23") _, out("v24") _,
                out("v25") _, out("v26") _, out("v27") _, out("v28") _, out("v29") _,
                out("v30") _, out("v31") _,
                options(nostack)
            );
        }
    };
}

#[inline(always)]
fn pad_keccak_input<const B: usize, const P: usize>(
    padded: &mut [u8; P],
    input: &[u8],
    padded_start: usize,
    input_start: usize,
) {
    let padded_end = padded_start + B;
    padded[padded_start..padded_end].copy_from_slice(&input[input_start..input_start + B]);
    padded[padded_end] |= 0x01;
    padded[padded_start + 135] |= 0x80;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{hex, keccak256};
    use proptest::proptest;
    use std::time::Instant;

    /// Differential test reference against the `keccak256` function from `alloy_primitives`, which
    /// uses the `tiny-keccak` crate as a backend.
    fn reference<const BLOCK_SIZE: usize>(input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), BLOCK_SIZE * 2);
        assert_eq!(output.len(), 64);
        output[..32].copy_from_slice(&*keccak256(&input[..BLOCK_SIZE]));
        output[32..].copy_from_slice(&*keccak256(&input[BLOCK_SIZE..]));
    }

    /// Differential test reference against the `keccak256` function from `XKCP`, using
    /// Dani's xkcp-rs bindings.
    fn reference_xkcp<const BLOCK_SIZE: usize>(input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), BLOCK_SIZE * 2);
        assert_eq!(output.len(), 64);
        xkcp_rs::keccak256(
            &input[..BLOCK_SIZE],
            output[..32].as_mut().try_into().unwrap(),
        );
        xkcp_rs::keccak256(
            &input[BLOCK_SIZE..],
            output[32..].as_mut().try_into().unwrap(),
        );
    }

    #[test]
    fn test_single_zeros() {
        const BLOCK_SIZE: usize = 32;

        let input = [0u8; 32];
        let mut output = [0u8; 32];
        simd_keccak256_single::<BLOCK_SIZE>(&input, &mut output);
        assert_eq!(output, *keccak256(input));
    }

    #[test]
    fn test_keccak256_zeros() {
        const BLOCK_SIZE: usize = 32;

        let input = [0u8; 64];
        let mut output = [0u8; 64];
        let mut expected = [0u8; 64];
        simd_keccak256_double::<BLOCK_SIZE>(&input, &mut output);
        reference::<BLOCK_SIZE>(&input, &mut expected);
        assert_eq!(hex::encode(&output), hex::encode(&expected));
    }

    #[test]
    fn test_keccak256_zero_len() {
        const BLOCK_SIZE: usize = 0;

        let input = [];
        let mut output = [0u8; 64];
        let mut expected = [0u8; 64];
        simd_keccak256_double::<BLOCK_SIZE>(&input, &mut output);
        reference::<BLOCK_SIZE>(&input, &mut expected);
        assert_eq!(hex::encode(&output), hex::encode(&expected));
    }

    #[test]
    fn test_keccak256_max_len() {
        const BLOCK_SIZE: usize = 135;

        let input = [0u8; 270];
        let mut output = [0u8; 64];
        let mut expected = [0u8; 64];
        simd_keccak256_double::<BLOCK_SIZE>(&input, &mut output);
        reference::<BLOCK_SIZE>(&input, &mut expected);
        assert_eq!(hex::encode(&output), hex::encode(&expected));
    }

    #[test]
    fn test_micro_bench_fixed32() {
        const BLOCK_SIZE: usize = 32;

        let input = [0u8; BLOCK_SIZE * 2];
        let mut output = [0u8; 64];
        let mut expected = [0u8; 64];

        let mut now = Instant::now();
        simd_keccak256_32b_double(&input, &mut output);
        println!("simd_keccak256_32b: {:?}", now.elapsed());

        now = Instant::now();
        reference::<BLOCK_SIZE>(&input, &mut expected);
        println!("reference: {:?}", now.elapsed());
        assert_eq!(hex::encode(&output), hex::encode(&expected));

        now = Instant::now();
        reference_xkcp::<BLOCK_SIZE>(&input, &mut expected);
        println!("reference_xkcp: {:?}", now.elapsed());
        assert_eq!(hex::encode(&output), hex::encode(&expected));
    }

    #[test]
    fn test_micro_bench_varlen() {
        const BLOCK_SIZE: usize = 128;

        let input = [0u8; BLOCK_SIZE * 2];
        let mut output = [0u8; 64];
        let mut expected = [0u8; 64];

        let mut now = Instant::now();
        simd_keccak256_double::<BLOCK_SIZE>(&input, &mut output);
        println!("simd_keccak256_32b: {:?}", now.elapsed());

        now = Instant::now();
        reference::<BLOCK_SIZE>(&input, &mut expected);
        println!("reference: {:?}", now.elapsed());
        assert_eq!(hex::encode(&output), hex::encode(&expected));

        now = Instant::now();
        reference_xkcp::<BLOCK_SIZE>(&input, &mut expected);
        println!("reference_xkcp: {:?}", now.elapsed());
        assert_eq!(hex::encode(&output), hex::encode(&expected));
    }

    proptest! {
        #[test]
        fn fuzz_diff_keccak32b(input: [u8; 64]) {
            const BLOCK_SIZE: usize = 32;

            let mut output = [0u8; 64];
            let mut expected = [0u8; 64];
            simd_keccak256_double::<BLOCK_SIZE>(&input, &mut output);
            simd_keccak256_32b_double(&input, &mut expected);
            assert_eq!(hex::encode(&output), hex::encode(&expected));
        }

        #[test]
        fn fuzz_diff_keccak32b_single(input: [u8; 32]) {
            const BLOCK_SIZE: usize = 32;

            let mut output = [0u8; 32];
            let mut expected = [0u8; 32];
            simd_keccak256_single::<BLOCK_SIZE>(&input, &mut output);
            simd_keccak256_32b_single(&input, &mut expected);
            assert_eq!(hex::encode(&output), hex::encode(&expected));
        }

        #[test]
        fn fuzz_diff_keccak64b(input: [u8; 128]) {
            const BLOCK_SIZE: usize = 64;

            let mut output = [0u8; 64];
            let mut expected = [0u8; 64];
            simd_keccak256_double::<BLOCK_SIZE>(&input, &mut output);
            simd_keccak256_64b_double(&input, &mut expected);
            assert_eq!(hex::encode(&output), hex::encode(&expected));
        }

        #[test]
        fn fuzz_diff_keccak64b_single(input: [u8; 64]) {
            const BLOCK_SIZE: usize = 64;

            let mut output = [0u8; 32];
            let mut expected = [0u8; 32];
            simd_keccak256_single::<BLOCK_SIZE>(&input, &mut output);
            simd_keccak256_64b_single(&input, &mut expected);
            assert_eq!(hex::encode(&output), hex::encode(&expected));
        }

        #[test]
        fn fuzz_keccak256_32b(input: [u8; 64]) {
            const BLOCK_SIZE: usize = 32;

            let mut output = [0u8; 64];
            let mut expected = [0u8; 64];
            simd_keccak256_double::<BLOCK_SIZE>(&input, &mut output);
            reference::<BLOCK_SIZE>(&input, &mut expected);
            assert_eq!(hex::encode(&output), hex::encode(&expected));
        }

        #[test]
        fn fuzz_keccak256_64b(input: [u8; 128]) {
            const BLOCK_SIZE: usize = 64;

            let mut output = [0u8; 64];
            let mut expected = [0u8; 64];
            simd_keccak256_double::<BLOCK_SIZE>(&input, &mut output);
            reference::<BLOCK_SIZE>(&input, &mut expected);
            assert_eq!(hex::encode(&output), hex::encode(&expected));
        }

        #[test]
        fn fuzz_keccak256_128b(input: [u8; 256]) {
            const BLOCK_SIZE: usize = 128;

            let mut output = [0u8; 64];
            let mut expected = [0u8; 64];
            simd_keccak256_double::<BLOCK_SIZE>(&input, &mut output);
            reference::<BLOCK_SIZE>(&input, &mut expected);
            assert_eq!(hex::encode(&output), hex::encode(&expected));
        }
    }
}
