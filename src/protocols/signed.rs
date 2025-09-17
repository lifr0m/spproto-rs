use aws_lc_rs::signature::{Ed25519KeyPair, UnparsedPublicKey};
use thiserror::Error;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Error, Debug)]
pub enum TransmitError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid signature or peer public key")]
    InvalidSignature,
}

pub struct SignedProtocol {
    stream: TcpStream,
    key_pair: Ed25519KeyPair,
    peer_public_key: UnparsedPublicKey<Vec<u8>>,
}

impl SignedProtocol {
    pub fn new(
        stream: TcpStream,
        key_pair: Ed25519KeyPair,
        peer_public_key: UnparsedPublicKey<Vec<u8>>,
    ) -> Self {
        Self { stream, key_pair, peer_public_key }
    }
    
    pub fn destruct(self) -> TcpStream {
        self.stream
    }
    
    pub async fn send(&mut self, message: &[u8]) -> Result<(), TransmitError> {
        let signature = self.key_pair.sign(message);
        self.stream.write_u64_le(signature.as_ref().len() as u64).await?;
        self.stream.write_all(signature.as_ref()).await?;

        self.stream.write_u64_le(message.len() as u64).await?;
        self.stream.write_all(message).await?;

        self.stream.flush().await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, TransmitError> {
        let length = self.stream.read_u64_le().await? as usize;
        let mut signature = vec![0; length];
        self.stream.read_exact(&mut signature).await?;

        let length = self.stream.read_u64_le().await? as usize;
        let mut message = vec![0; length];
        self.stream.read_exact(&mut message).await?;

        self.peer_public_key.verify(&message, &signature)
            .map_err(|_| TransmitError::InvalidSignature)?;

        Ok(message)
    }
}
