use xsalsa20poly1305::aead::{generic_array::GenericArray, Aead, NewAead};
use xsalsa20poly1305::XSalsa20Poly1305;

fn test1() {
    let key = GenericArray::from_slice(b"an example very very secret key.");
    let cipher = XSalsa20Poly1305::new(key);

    let nonce = GenericArray::from_slice(b"extra long unique nonce!");

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
