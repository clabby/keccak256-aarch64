//! Contains a (restricted) Keccak256 implementation for ARMv8-A.

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

/// Double keccak256 on ARMv8-A. Input size restricted to 64 bytes, 32 bytes on either half of the
/// slice.
///
/// Credits to @recmo for the reference K12 implementation in [Goldilocks](https://github.com/recmo/goldilocks/blob/main/pcs/src/k12/aarch64.rs).
///
/// Keccak256 bitrate = `1088`, capacity = `512`
#[allow(asm_sub_register)]
pub fn simd_keccak256_32b(input: &[u8], output: &mut [u8]) {
    assert_eq!(input.len(), 64);
    assert_eq!(output.len(), 64);

    unsafe {
        core::arch::asm!("
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
        include_str!("keccak_f1600.asm"),
        "
            // Write output (first 256 bits of state)
            st4.d {{ v0- v3}}[0], [{output}], #32
            st4.d {{ v0- v3}}[1], [{output}], #32

        ",
            input = inout(reg) input.as_ptr() => _,
            output = inout(reg) output.as_mut_ptr() => _,
            loop = inout(reg) 24 => _,
            rc = inout(reg) RC.as_ptr() => _,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{hex, keccak256};
    use proptest::proptest;

    /// Differential test reference against the `keccak256` function from `alloy_primitives`, which
    /// uses the `tiny-keccak` crate as a backend.
    fn reference(input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), 64);
        assert_eq!(output.len(), 64);
        output[..32].copy_from_slice(&*keccak256(&input[..32]));
        output[32..].copy_from_slice(&*keccak256(&input[32..]));
    }

    #[test]
    fn test_keccak256_zeros() {
        let input = [0u8; 64];
        let mut output = [0u8; 64];
        let mut expected = [0u8; 64];
        simd_keccak256_32b(&input, &mut output);
        reference(&input, &mut expected);
        assert_eq!(hex::encode(&output), hex::encode(&expected));
    }

    proptest! {
        #[test]
        fn fuzz_keccak256(input: [u8; 64]) {
            let mut output = [0u8; 64];
            let mut expected = [0u8; 64];
            simd_keccak256_32b(&input, &mut output);
            reference(&input, &mut expected);
            assert_eq!(hex::encode(&output), hex::encode(&expected));
        }
    }
}
