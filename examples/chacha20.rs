use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

fn test1() {
    let key = Key::from_slice(b"an example very very secret key.");
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(b"unique nonce");

    let ciphertext = cipher
        .encrypt(nonce, b"plaintext message".as_ref())
        .expect("encryption failure!");
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");

    assert_eq!(&plaintext, b"plaintext message");
}

fn main() {
    test1();
}
