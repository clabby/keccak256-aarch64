use criterion::{criterion_group, criterion_main, Criterion};
use keccak256_aarch64_simd::{simd_keccak256_64b_double, simd_keccak256_64b_single};
use rand::Rng;

/// Differential test reference against the `keccak256` function from `alloy_primitives`, which
/// uses the `tiny-keccak` crate as a backend.
fn reference_alloy_double<const BLOCK_SIZE: usize>(input: &[u8], output: &mut [u8]) {
    assert_eq!(input.len(), BLOCK_SIZE * 2);
    assert_eq!(output.len(), 64);
    output[..32].copy_from_slice(&*alloy_primitives::keccak256(&input[..BLOCK_SIZE]));
    output[32..].copy_from_slice(&*alloy_primitives::keccak256(&input[BLOCK_SIZE..]));
}

fn reference_alloy_single<const BLOCK_SIZE: usize>(input: &[u8], output: &mut [u8]) {
    assert_eq!(input.len(), BLOCK_SIZE);
    assert_eq!(output.len(), 32);
    output[..].copy_from_slice(&*alloy_primitives::keccak256(&input));
}

/// Differential test reference against the `keccak256` function from `XKCP`, using
/// Dani's xkcp-rs bindings.
fn reference_xkcp_double<const BLOCK_SIZE: usize>(input: &[u8], output: &mut [u8]) {
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

fn reference_xkcp_single<const BLOCK_SIZE: usize>(input: &[u8], output: &mut [u8]) {
    assert_eq!(input.len(), BLOCK_SIZE);
    assert_eq!(output.len(), 32);
    xkcp_rs::keccak256(
        &input[..BLOCK_SIZE],
        output[..].as_mut().try_into().unwrap(),
    );
}

fn zeros(c: &mut Criterion) {
    let mut g = c.benchmark_group("keccak256::zeros");

    g.bench_function("double 64 byte input (alloy [tiny-keccak])", |b| {
        let input = [0u8; 128];
        b.iter(|| reference_alloy_double::<64>(&input, &mut [0u8; 64]));
    });
    g.bench_function("double 64 byte input (xkcp)", |b| {
        let input = [0u8; 128];
        b.iter(|| reference_xkcp_double::<64>(&input, &mut [0u8; 64]));
    });
    g.bench_function("double 64 byte input (simd keccak)", |b| {
        let input = [0u8; 128];
        b.iter(|| simd_keccak256_64b_double(&input, &mut [0u8; 64]));
    });

    g.bench_function("single 64 byte input (alloy [tiny-keccak])", |b| {
        let input = [0u8; 64];
        b.iter(|| reference_alloy_single::<64>(&input, &mut [0u8; 32]));
    });
    g.bench_function("single 64 byte input (xkcp)", |b| {
        let input = [0u8; 64];
        b.iter(|| reference_xkcp_single::<64>(&input, &mut [0u8; 32]));
    });
    g.bench_function("single 64 byte input (simd keccak)", |b| {
        let input = [0u8; 64];
        b.iter(|| simd_keccak256_64b_single(&input, &mut [0u8; 32]));
    });
}

fn rand_bytes(c: &mut Criterion) {
    let mut g = c.benchmark_group("keccak256::rand_bytes");

    #[inline]
    fn rand_bytes<const N: usize>() -> [u8; N] {
        let mut rng = rand::thread_rng();
        let mut input = [0u8; N];
        rng.fill(&mut input[..]);
        input
    }

    g.bench_function("double 64 byte input (alloy [tiny-keccak])", |b| {
        let input = rand_bytes::<128>();
        b.iter(|| reference_alloy_double::<64>(&input, &mut [0u8; 64]));
    });
    g.bench_function("double 64 byte input (xkcp)", |b| {
        let input = rand_bytes::<128>();
        b.iter(|| reference_xkcp_double::<64>(&input, &mut [0u8; 64]));
    });
    g.bench_function("double 64 byte input (simd keccak)", |b| {
        let input = rand_bytes::<128>();
        b.iter(|| simd_keccak256_64b_double(&input, &mut [0u8; 64]));
    });

    g.bench_function("single 64 byte input (alloy [tiny-keccak])", |b| {
        let input = rand_bytes::<64>();
        b.iter(|| reference_alloy_single::<64>(&input, &mut [0u8; 32]));
    });
    g.bench_function("single 64 byte input (xkcp)", |b| {
        let input = rand_bytes::<64>();
        b.iter(|| reference_xkcp_single::<64>(&input, &mut [0u8; 32]));
    });
    g.bench_function("single 64 byte input (simd keccak)", |b| {
        let input = rand_bytes::<64>();
        b.iter(|| simd_keccak256_64b_single(&input, &mut [0u8; 32]));
    });
}

criterion_group!(benches, zeros, rand_bytes);
criterion_main!(benches);
