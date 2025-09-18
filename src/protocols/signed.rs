use ed25519::signature::Signer;
use ed25519::Signature;
use ed25519_dalek::{SigningKey, VerifyingKey};
use thiserror::Error;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("signature: {0}")]
    Signature(#[from] ed25519::Error),
}

pub struct Protocol {
    stream: TcpStream,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Protocol {
    pub fn new(
        stream: TcpStream,
        b_signing_key: [u8; 32],
        b_verifying_key: [u8; 32],
    ) -> Result<Self, Error> {
        let signing_key = SigningKey::from_bytes(&b_signing_key);
        let verifying_key = VerifyingKey::from_bytes(&b_verifying_key)?;

        Ok(Self { stream, signing_key, verifying_key })
    }

    pub fn destruct(self) -> TcpStream {
        self.stream
    }

    pub async fn send(&mut self, message: &[u8]) -> Result<(), Error> {
        let signature = self.signing_key.sign(message);
        self.stream.write_all(&signature.to_bytes()).await?;

        self.stream.write_u64_le(message.len() as u64).await?;
        self.stream.write_all(message).await?;

        self.stream.flush().await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, Error> {
        let mut signature = [0; 64];
        self.stream.read_exact(&mut signature).await?;
        let signature = Signature::from_bytes(&signature);

        let length = self.stream.read_u64_le().await? as usize;
        let mut message = vec![0; length];
        self.stream.read_exact(&mut message).await?;

        self.verifying_key.verify_strict(&message, &signature)?;

        Ok(message)
    }
}
