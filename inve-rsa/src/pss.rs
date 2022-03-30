use alloc::vec;
use alloc::vec::Vec;

use digest::DynDigest;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::algorithms::mgf1_xor;
use crate::errors::{Error, Result};
use crate::key::{PrivateKey, PublicKey};

pub fn verify<PK: PublicKey>(
    pub_key: &PK,
    hashed: &[u8],
    sig: &[u8],
    digest: &mut dyn DynDigest,
) -> Result<()> {
    if sig.len() != pub_key.size() {
        return Err(Error::Verification);
    }

    let em_bits = pub_key.n().bits() - 1;
    let em_len = (em_bits + 7) / 8;
    let mut em = pub_key.raw_encryption_primitive(sig, em_len)?;

    emsa_pss_verify(hashed, &mut em, em_bits, None, digest)
}

pub fn sign<T: RngCore + ?Sized, S: CryptoRng + RngCore, SK: PrivateKey>(
    rng: &mut T,
    blind_rng: Option<&mut S>,
    priv_key: &SK,
    hashed: &[u8],
    salt_len: Option<usize>,
    digest: &mut dyn DynDigest,
) -> Result<Vec<u8>> {
    let salt_len = salt_len.unwrap_or_else(|| priv_key.size() - 2 - digest.output_size());

    let mut salt = vec![0; salt_len];
    rng.fill_bytes(&mut salt[..]);

    sign_pss_with_salt(blind_rng, priv_key, hashed, &salt, digest)
}

fn sign_pss_with_salt<T: CryptoRng + RngCore, SK: PrivateKey>(
    blind_rng: Option<&mut T>,
    priv_key: &SK,
    hashed: &[u8],
    salt: &[u8],
    digest: &mut dyn DynDigest,
) -> Result<Vec<u8>> {
    let em_bits = priv_key.n().bits() - 1;
    let em = emsa_pss_encode(hashed, em_bits, salt, digest)?;

    priv_key.raw_decryption_primitive(blind_rng, &em, priv_key.size())
}

fn emsa_pss_encode(
    m_hash: &[u8],
    em_bits: usize,
    salt: &[u8],
    hash: &mut dyn DynDigest,
) -> Result<Vec<u8>> {
    let h_len = hash.output_size();
    let s_len = salt.len();
    let em_len = (em_bits + 7) / 8;

    if m_hash.len() != h_len {
        return Err(Error::InputNotHashed);
    }

    if em_len < h_len + s_len + 2 {
        return Err(Error::Internal);
    }

    let mut em = vec![0; em_len];

    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..(em_len - 1) - db.len()];

    let prefix = [0u8; 8];

    hash.update(&prefix);
    hash.update(m_hash);
    hash.update(salt);

    let hashed = hash.finalize_reset();
    h.copy_from_slice(&hashed);

    db[em_len - s_len - h_len - 2] = 0x01;
    db[em_len - s_len - h_len - 1..].copy_from_slice(salt);

    mgf1_xor(db, hash, &h);

    db[0] &= 0xFF >> (8 * em_len - em_bits);

    em[em_len - 1] = 0xBC;

    Ok(em)
}

fn emsa_pss_verify(
    m_hash: &[u8],
    em: &mut [u8],
    em_bits: usize,
    s_len: Option<usize>,
    hash: &mut dyn DynDigest,
) -> Result<()> {
    let h_len = hash.output_size();
    if m_hash.len() != h_len {
        return Err(Error::Verification);
    }

    let em_len = em.len();
    if em_len < h_len + s_len.unwrap_or_default() + 2 {
        return Err(Error::Verification);
    }

    if em[em.len() - 1] != 0xBC {
        return Err(Error::Verification);
    }

    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..h_len];

    if db[0] & (0xFF << (8 - (8 * em_len - em_bits))) != 0 {
        return Err(Error::Verification);
    }

    mgf1_xor(db, hash, &*h);

    db[0] &= 0xFF >> (8 * em_len - em_bits);

    let s_len = match s_len {
        None => (0..=em_len - (h_len + 2))
            .rev()
            .try_fold(None, |state, i| match (state, db[em_len - h_len - i - 2]) {
                (Some(i), _) => Ok(Some(i)),
                (_, 1) => Ok(Some(i)),
                (_, 0) => Ok(None),
                _ => Err(Error::Verification),
            })?
            .ok_or(Error::Verification)?,
        Some(s_len) => {
            let (zeroes, rest) = db.split_at(em_len - h_len - s_len - 2);
            if zeroes.iter().any(|e| *e != 0x00) || rest[0] != 0x01 {
                return Err(Error::Verification);
            }

            s_len
        }
    };

    let salt = &db[db.len() - s_len..];

    let prefix = [0u8; 8];

    hash.update(&prefix[..]);
    hash.update(m_hash);
    hash.update(salt);
    let h0 = hash.finalize_reset();

    if h0.ct_eq(h).into() {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

#[cfg(test)]
mod test {
    use crate::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

    use hex_literal::hex;
    use num_bigint::BigUint;
    use num_traits::{FromPrimitive, Num};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    use sha1::{Digest, Sha1};

    fn get_private_key() -> RsaPrivateKey {
        RsaPrivateKey::from_components(
            BigUint::from_str_radix("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077", 10).unwrap(),
            BigUint::from_u64(65537).unwrap(),
            BigUint::from_str_radix("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861", 10).unwrap(),
            vec![
                BigUint::from_str_radix("98920366548084643601728869055592650835572950932266967461790948584315647051443",10).unwrap(),
                BigUint::from_str_radix("94560208308847015747498523884063394671606671904944666360068158221458669711639", 10).unwrap()
            ],
        )
    }

    #[test]
    fn test_verify_pss() {
        let priv_key = get_private_key();

        let tests = [(
            "test\n",
            hex!(
                "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
                "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962f"
            ),
        )];
        let pub_key: RsaPublicKey = priv_key.into();

        for (text, sig) in &tests {
            let digest = Sha1::digest(text.as_bytes()).to_vec();
            let rng = ChaCha8Rng::from_seed([42; 32]);
            pub_key
                .verify(PaddingScheme::new_pss::<Sha1, _>(rng), &digest, sig)
                .expect("failed to verify");
        }
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let priv_key = get_private_key();

        let tests = ["test\n"];
        let rng = ChaCha8Rng::from_seed([42; 32]);

        for test in &tests {
            let digest = Sha1::digest(test.as_bytes()).to_vec();
            let sig = priv_key
                .sign_blinded(
                    &mut rng.clone(),
                    PaddingScheme::new_pss::<Sha1, _>(rng.clone()),
                    &digest,
                )
                .expect("failed to sign");

            priv_key
                .verify(
                    PaddingScheme::new_pss::<Sha1, _>(rng.clone()),
                    &digest,
                    &sig,
                )
                .expect("failed to verify");
        }
    }
}
