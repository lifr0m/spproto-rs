use ed25519_dalek::SigningKey;
use rand::TryRngCore;

pub fn generate_signing_key() -> [u8; 32] {
    let mut rng = rand::rngs::OsRng
        .unwrap_err();
    SigningKey::generate(&mut rng)
        .to_bytes()
}

pub fn get_verifying_key(b_signing_key: [u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(&b_signing_key)
        .verifying_key()
        .to_bytes()
}
