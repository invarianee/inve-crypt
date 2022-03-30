use alloc::vec;
use digest::DynDigest;
use num_bigint::traits::ModInverse;
use num_bigint::{BigUint, RandPrime};
#[allow(unused_imports)]
use num_traits::Float;
use num_traits::{FromPrimitive, One, Zero};
use rand_core::{CryptoRng, RngCore};

use crate::errors::{Error, Result};
use crate::key::RsaPrivateKey;

const EXP: u64 = 65537;

pub fn generate_multi_prime_key<R: RngCore + CryptoRng>(
    rng: &mut R,
    nprimes: usize,
    bit_size: usize,
) -> Result<RsaPrivateKey> {
    let exp = BigUint::from_u64(EXP).expect("invalid static exponent");
    generate_multi_prime_key_with_exp(rng, nprimes, bit_size, &exp)
}

pub fn generate_multi_prime_key_with_exp<R: RngCore + CryptoRng>(
    rng: &mut R,
    nprimes: usize,
    bit_size: usize,
    exp: &BigUint,
) -> Result<RsaPrivateKey> {
    if nprimes < 2 {
        return Err(Error::NprimesTooSmall);
    }

    if bit_size < 64 {
        let prime_limit = (1u64 << (bit_size / nprimes) as u64) as f64;

        let mut pi = prime_limit / (prime_limit.ln() - 1f64);
        pi /= 4f64;
        pi /= 2f64;

        if pi < nprimes as f64 {
            return Err(Error::TooFewPrimes);
        }
    }

    let mut primes = vec![BigUint::zero(); nprimes];
    let n_final: BigUint;
    let d_final: BigUint;

    'next: loop {
        let mut todo = bit_size;
        if nprimes >= 7 {
            todo += (nprimes - 2) / 5;
        }

        for (i, prime) in primes.iter_mut().enumerate() {
            *prime = rng.gen_prime(todo / (nprimes - i));
            todo -= prime.bits();
        }

        for (i, prime1) in primes.iter().enumerate() {
            for prime2 in primes.iter().take(i) {
                if prime1 == prime2 {
                    continue 'next;
                }
            }
        }

        let mut n = BigUint::one();
        let mut totient = BigUint::one();

        for prime in &primes {
            n *= prime;
            totient *= prime - BigUint::one();
        }

        if n.bits() != bit_size {
            continue 'next;
        }

        if let Some(d) = exp.mod_inverse(totient) {
            n_final = n;
            d_final = d.to_biguint().unwrap();
            break;
        }
    }

    Ok(RsaPrivateKey::from_components(
        n_final,
        exp.clone(),
        d_final,
        primes,
    ))
}

pub fn mgf1_xor(out: &mut [u8], digest: &mut dyn DynDigest, seed: &[u8]) {
    let mut counter = [0u8; 4];
    let mut i = 0;

    const MAX_LEN: u64 = core::u32::MAX as u64 + 1;
    assert!(out.len() as u64 <= MAX_LEN);

    while i < out.len() {
        let mut digest_input = vec![0u8; seed.len() + 4];
        digest_input[0..seed.len()].copy_from_slice(seed);
        digest_input[seed.len()..].copy_from_slice(&counter);

        digest.update(digest_input.as_slice());
        let digest_output = &*digest.finalize_reset();
        let mut j = 0;
        loop {
            if j >= digest_output.len() || i >= out.len() {
                break;
            }

            out[i] ^= digest_output[j];
            j += 1;
            i += 1;
        }
        inc_counter(&mut counter);
    }
}

fn inc_counter(counter: &mut [u8; 4]) {
    for i in (0..4).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            return;
        }
    }
}
