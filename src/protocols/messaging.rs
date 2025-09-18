use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce};
use thiserror::Error;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("aead: {0}")]
    Aead(#[from] chacha20poly1305::Error),
}

pub struct Protocol {
    stream: TcpStream,
    cipher: ChaCha20Poly1305,
}

impl Protocol {
    pub fn new(stream: TcpStream, b_key: [u8; 32]) -> Self {
        let key = Key::from(b_key);
        let cipher = ChaCha20Poly1305::new(&key);

        Self { stream, cipher }
    }

    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        let nonce = ChaCha20Poly1305::generate_nonce()
            .expect("nonce generation failed");
        let ciphertext = self.cipher.encrypt(&nonce, plaintext)?;

        self.stream.write_all(&nonce).await?;

        self.stream.write_u64_le(ciphertext.len() as u64).await?;
        self.stream.write_all(&ciphertext).await?;

        self.stream.flush().await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, Error> {
        let mut nonce = Nonce::default();
        self.stream.read_exact(&mut nonce).await?;

        let length = self.stream.read_u64_le().await? as usize;
        let mut ciphertext = vec![0; length];
        self.stream.read_exact(&mut ciphertext).await?;

        let plaintext = self.cipher.decrypt(&nonce, ciphertext.as_ref())?;

        Ok(plaintext)
    }
}
