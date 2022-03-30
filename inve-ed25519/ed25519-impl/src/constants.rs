pub const SIGNATURE_LENGTH: usize = 64;

pub const SECRET_KEY_LENGTH: usize = 32;

pub const PUBLIC_KEY_LENGTH: usize = 32;

pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

const EXPANDED_SECRET_KEY_KEY_LENGTH: usize = 32;

const EXPANDED_SECRET_KEY_NONCE_LENGTH: usize = 32;

pub const EXPANDED_SECRET_KEY_LENGTH: usize =
    EXPANDED_SECRET_KEY_KEY_LENGTH + EXPANDED_SECRET_KEY_NONCE_LENGTH;
