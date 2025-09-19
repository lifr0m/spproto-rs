use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("cipher: {0}")]
    Cipher(#[from] chacha20poly1305::Error),

    #[error("protocol: {0}")]
    Protocol(String),
}

pub struct Protocol {
    cipher: ChaCha20Poly1305,
}

impl Protocol {
    pub fn new(b_key: [u8; 32]) -> Self {
        let key = Key::from(b_key);
        let cipher = ChaCha20Poly1305::new(&key);

        Self { cipher }
    }

    pub fn pack(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = ChaCha20Poly1305::generate_nonce()
            .expect("nonce generation failed");
        Ok(self.cipher.encrypt(&nonce, msg)?)
    }

    pub fn unpack(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let (nonce, msg) = msg.split_at_checked(12)
            .ok_or_else(|| Error::Protocol("msg has invalid length".to_string()))?;
        let nonce = Nonce::try_from(nonce)
            .unwrap();
        Ok(self.cipher.decrypt(&nonce, msg)?)
    }
}
