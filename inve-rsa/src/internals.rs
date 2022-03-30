use alloc::borrow::Cow;
use alloc::vec;
use alloc::vec::Vec;
use num_bigint::{BigInt, BigUint, IntoBigInt, IntoBigUint, ModInverse, RandBigInt, ToBigInt};
use num_traits::{One, Signed, Zero};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::errors::{Error, Result};
use crate::key::{PublicKeyParts, RsaPrivateKey};

#[inline]
pub fn encrypt<K: PublicKeyParts>(key: &K, m: &BigUint) -> BigUint {
    m.modpow(key.e(), key.n())
}

#[inline]
pub fn decrypt<R: RngCore + CryptoRng>(
    mut rng: Option<&mut R>,
    priv_key: &RsaPrivateKey,
    c: &BigUint,
) -> Result<BigUint> {
    if c >= priv_key.n() {
        return Err(Error::Decryption);
    }

    if priv_key.n().is_zero() {
        return Err(Error::Decryption);
    }

    let mut ir = None;

    let c = if let Some(ref mut rng) = rng {
        let (blinded, unblinder) = blind(rng, priv_key, c);
        ir = Some(unblinder);
        Cow::Owned(blinded)
    } else {
        Cow::Borrowed(c)
    };

    let m = match priv_key.precomputed {
        None => c.modpow(priv_key.d(), priv_key.n()),
        Some(ref precomputed) => {
            let p = &priv_key.primes()[0];
            let q = &priv_key.primes()[1];

            let mut m = c.modpow(&precomputed.dp, p).into_bigint().unwrap();
            let mut m2 = c.modpow(&precomputed.dq, q).into_bigint().unwrap();

            m -= &m2;

            let mut primes: Vec<_> = priv_key
                .primes()
                .iter()
                .map(ToBigInt::to_bigint)
                .map(Option::unwrap)
                .collect();

            while m.is_negative() {
                m += &primes[0];
            }
            m *= &precomputed.qinv;
            m %= &primes[0];
            m *= &primes[1];
            m += &m2;

            let mut c = c.into_owned().into_bigint().unwrap();
            for (i, value) in precomputed.crt_values.iter().enumerate() {
                let prime = &primes[2 + i];
                m2 = c.modpow(&value.exp, prime);
                m2 -= &m;
                m2 *= &value.coeff;
                m2 %= prime;
                while m2.is_negative() {
                    m2 += prime;
                }
                m2 *= &value.r;
                m += &m2;
            }

            for prime in primes.iter_mut() {
                prime.zeroize();
            }
            primes.clear();
            c.zeroize();
            m2.zeroize();

            m.into_biguint().expect("failed to decrypt")
        }
    };

    match ir {
        Some(ref ir) => Ok(unblind(priv_key, &m, &ir)),
        None => Ok(m),
    }
}

#[inline]
pub fn decrypt_and_check<R: RngCore + CryptoRng>(
    rng: Option<&mut R>,
    priv_key: &RsaPrivateKey,
    c: &BigUint,
) -> Result<BigUint> {
    let m = decrypt(rng, priv_key, c)?;

    let check = encrypt(priv_key, &m);

    if c != &check {
        return Err(Error::Internal);
    }

    Ok(m)
}

pub fn blind<R: RngCore + CryptoRng, K: PublicKeyParts>(
    rng: &mut R,
    key: &K,
    c: &BigUint,
) -> (BigUint, BigUint) {
    let mut r: BigUint;
    let mut ir: Option<BigInt>;
    let unblinder;
    loop {
        r = rng.gen_biguint_below(key.n());
        if r.is_zero() {
            r = BigUint::one();
        }
        ir = r.clone().mod_inverse(key.n());
        if let Some(ir) = ir {
            if let Some(ub) = ir.into_biguint() {
                unblinder = ub;
                break;
            }
        }
    }

    let c = {
        let mut rpowe = r.modpow(key.e(), key.n());
        let mut c = c * &rpowe;
        c %= key.n();

        rpowe.zeroize();

        c
    };

    (c, unblinder)
}

pub fn unblind(key: impl PublicKeyParts, m: &BigUint, unblinder: &BigUint) -> BigUint {
    (m * unblinder) % key.n()
}

#[inline]
pub fn left_pad(input: &[u8], size: usize) -> Vec<u8> {
    let n = if input.len() > size {
        size
    } else {
        input.len()
    };

    let mut out = vec![0u8; size];
    out[size - n..].copy_from_slice(input);
    out
}
