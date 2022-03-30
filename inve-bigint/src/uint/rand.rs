use super::UInt;
use crate::{Limb, NonZero, Random, RandomMod};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeLess;

#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
impl<const LIMBS: usize> Random for UInt<LIMBS> {
    fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        let mut limbs = [Limb::ZERO; LIMBS];

        for limb in &mut limbs {
            *limb = Limb::random(&mut rng)
        }

        limbs.into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
impl<const LIMBS: usize> RandomMod for UInt<LIMBS> {
    fn random_mod(mut rng: impl CryptoRng + RngCore, modulus: &NonZero<Self>) -> Self {
        let mut n = Self::ZERO;

        let mut n_limbs = modulus.bits() / Limb::BIT_SIZE;
        if n_limbs < LIMBS {
            n_limbs += 1;
        }

        let modulus_hi =
            NonZero::new(modulus.limbs[n_limbs.saturating_sub(1)].saturating_add(Limb::ONE))
                .unwrap();

        loop {
            for i in 0..n_limbs {
                n.limbs[i] = if (i + 1 == n_limbs) && (*modulus_hi != Limb::MAX) {
                    Limb::random_mod(&mut rng, &modulus_hi)
                } else {
                    Limb::random(&mut rng)
                }
            }

            if n.ct_lt(modulus).into() {
                return n;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{NonZero, RandomMod, U256};
    use rand_core::SeedableRng;

    #[test]
    fn random_mod() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1);

        let modulus = NonZero::new(U256::from(42u8)).unwrap();
        let res = U256::random_mod(&mut rng, &modulus);

        assert_ne!(res, U256::ZERO);

        let modulus = NonZero::new(U256::from(0x10000000000000001u128)).unwrap();
        let res = U256::random_mod(&mut rng, &modulus);

        assert_ne!(res, U256::ZERO);
    }
}
