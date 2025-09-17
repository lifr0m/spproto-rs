use aws_lc_rs::aead::nonce_sequence::{Counter64, Counter64Builder};
use aws_lc_rs::aead::{Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, CHACHA20_POLY1305};
use thiserror::Error;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Error, Debug)]
pub enum TransmitError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("nonce sequence cannot be advanced")]
    NonceSeqNotAdvanceable,

    #[error("invalid ciphertext")]
    InvalidCiphertext,
}

pub struct MessagingProtocol {
    stream: TcpStream,
    sealing_key: SealingKey<Counter64>,
    opening_key: OpeningKey<Counter64>,
}

impl MessagingProtocol {
    pub fn new(stream: TcpStream, b_key: Vec<u8>) -> Self {
        let sealing_key = SealingKey::new(
            Self::new_unbound_key(&b_key),
            Self::new_nonce_seq(),
        );
        let opening_key = OpeningKey::new(
            Self::new_unbound_key(&b_key),
            Self::new_nonce_seq(),
        );

        Self { stream, sealing_key, opening_key }
    }

    fn new_unbound_key(b_key: &[u8]) -> UnboundKey {
        UnboundKey::new(&CHACHA20_POLY1305, b_key)
            .expect("invalid key length")
    }

    fn new_nonce_seq() -> Counter64 {
        Counter64Builder::new().build()
    }

    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), TransmitError> {
        let mut ciphertext = Vec::from(plaintext);
        self.sealing_key.seal_in_place_append_tag(Aad::empty(), &mut ciphertext)
            .map_err(|_| TransmitError::NonceSeqNotAdvanceable)?;

        self.stream.write_u64_le(ciphertext.len() as u64).await?;
        self.stream.write_all(&ciphertext).await?;

        self.stream.flush().await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, TransmitError> {
        let length = self.stream.read_u64_le().await? as usize;
        let mut ciphertext = vec![0; length];
        self.stream.read_exact(&mut ciphertext).await?;

        let mut in_out = ciphertext;
        let plaintext = self.opening_key.open_in_place(Aad::empty(), &mut in_out)
            .map_err(|_| TransmitError::InvalidCiphertext)?
            .to_vec();

        Ok(plaintext)
    }
}
