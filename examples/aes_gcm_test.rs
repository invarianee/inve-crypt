use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, Nonce};

fn aes256_test() {
    let key = Key::<Aes256Gcm>::from_slice(b"an example very very secret key.");
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(b"unique nonce");

    let ciphertext = cipher
        .encrypt(nonce, b"plaintext message".as_ref())
        .expect("encryption failure!");

    println!("ciphertext = {:#?}", ciphertext);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");

    assert_eq!(&plaintext, b"plaintext message");
}

fn aes128_test() {
    let key = Key::<Aes128Gcm>::from_slice(b"an example veryy");
    let cipher = Aes128Gcm::new(key);

    let nonce = Nonce::from_slice(b"unique nonce");

    let ciphertext = cipher
        .encrypt(nonce, b"plaintext message".as_ref())
        .expect("encryption failure!");

    println!("ciphertext = {:#?}", ciphertext);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");

    assert_eq!(&plaintext, b"plaintext message");
}

fn main() {
    aes256_test();
    aes128_test();
}
