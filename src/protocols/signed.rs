use ed25519::signature::Signer;
use ed25519::Signature;
use ed25519_dalek::{SigningKey, VerifyingKey};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("signature: {0}")]
    Signature(#[from] ed25519::Error),

    #[error("protocol: {0}")]
    Protocol(String),
}

pub struct Protocol {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Protocol {
    pub fn new(b_signing_key: [u8; 32], b_verifying_key: [u8; 32]) -> Result<Self, Error> {
        let signing_key = SigningKey::from(b_signing_key);
        let verifying_key = VerifyingKey::from_bytes(&b_verifying_key)?;

        Ok(Self { signing_key, verifying_key })
    }

    pub fn pack(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let signature = self.signing_key.sign(msg);
        Ok([&signature.to_bytes(), msg].concat())
    }

    pub fn unpack(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let (signature, msg) = msg.split_at_checked(64)
            .ok_or_else(|| Error::Protocol("msg has invalid length".to_string()))?;
        let signature = Signature::try_from(signature)
            .unwrap();
        self.verifying_key.verify_strict(msg, &signature)?;
        Ok(msg.to_vec())
    }
}
