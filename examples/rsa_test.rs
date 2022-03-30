fn test1() {
    use rand::rngs::OsRng;
    use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let data = b"hello world";
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = public_key
        .encrypt(&mut rng, padding, &data[..])
        .expect("failed to encrypt");
    assert_ne!(&data[..], &enc_data[..]);

    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let dec_data = private_key
        .decrypt(padding, &enc_data)
        .expect("failed to decrypt");
    assert_eq!(&data[..], &dec_data[..]);
}

fn test2() {
    use rand::rngs::OsRng;
    use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
    let mut rng = OsRng;

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let data = b"hello world";
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let enc_data = public_key
        .encrypt(&mut rng, padding, &data[..])
        .expect("failed to encrypt");
    assert_ne!(&data[..], &enc_data[..]);

    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let dec_data = private_key
        .decrypt(padding, &enc_data)
        .expect("failed to decrypt");
    assert_eq!(&data[..], &dec_data[..]);
}

fn test3() {
    use rand::rngs::OsRng;
    use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

    let mut rng = OsRng;
    let bits = 4096;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let data = b"hello world";
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = public_key
        .encrypt(&mut rng, padding, &data[..])
        .expect("failed to encrypt");
    assert_ne!(&data[..], &enc_data[..]);

    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let dec_data = private_key
        .decrypt(padding, &enc_data)
        .expect("failed to decrypt");
    assert_eq!(&data[..], &dec_data[..]);
}

fn test4() {
    use rand::rngs::OsRng;
    use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
    let mut rng = OsRng;

    let bits = 4096;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let data = b"hello world";
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let enc_data = public_key
        .encrypt(&mut rng, padding, &data[..])
        .expect("failed to encrypt");
    assert_ne!(&data[..], &enc_data[..]);

    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let dec_data = private_key
        .decrypt(padding, &enc_data)
        .expect("failed to decrypt");
    assert_eq!(&data[..], &dec_data[..]);
}

fn main() {
    test1();
    test2();
    test3();
    test4();
}
