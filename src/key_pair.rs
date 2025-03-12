use aws_lc_rs::error::KeyRejected;
use aws_lc_rs::pkcs8;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

pub fn generate_key_pair() -> pkcs8::Document {
    let key_pair = Ed25519KeyPair::generate()
        .expect("key pair generation error");
    key_pair.to_pkcs8()
        .expect("internal error serializing key pair")
}

pub fn get_public_key(b_key_pair: &[u8]) -> Result<Vec<u8>, KeyRejected> {
    let key_pair = Ed25519KeyPair::from_pkcs8(b_key_pair)?;
    Ok(Vec::from(key_pair.public_key().as_ref()))
}
