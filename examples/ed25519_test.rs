use ed25519_impl::*;
use rand::rngs::OsRng;

fn sign_verify() {
    let keypair: Keypair;
    let good_sig: Signature;
    let bad_sig: Signature;

    let good: &[u8] = "test message".as_bytes();
    let bad: &[u8] = "wrong message".as_bytes();

    let mut csprng = OsRng {};

    keypair = Keypair::generate(&mut csprng);
    good_sig = keypair.sign(&good);
    bad_sig = keypair.sign(&bad);

    assert!(
        keypair.verify(&good, &good_sig).is_ok(),
        "Verification of a valid signature failed!"
    );
    assert!(
        keypair.verify(&good, &bad_sig).is_err(),
        "Verification of a signature on a different message passed!"
    );
    assert!(
        keypair.verify(&bad, &good_sig).is_err(),
        "Verification of a signature on a different message passed!"
    );
}

fn main() {
    sign_verify();
}
