fn test1() {
    use ecdsa_p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand_core::OsRng;

    let signing_key = SigningKey::random(&mut OsRng);
    let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
    let signature: Signature = signing_key.sign(message);

    use ecdsa_p256::ecdsa::{signature::Verifier, VerifyingKey};

    let verifying_key = VerifyingKey::from(&signing_key);
    assert!(verifying_key.verify(message, &signature).is_ok());
}

fn main() {
    test1();
}
