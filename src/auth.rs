use crate::protocols::{messaging, signed};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use tokio::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Error, Debug)]
pub enum Error {
    #[error("signed proto: {0}")]
    SignedProto(#[from] signed::Error),

    #[error("kdf: {0}")]
    Kdf(#[from] hkdf::InvalidLength),

    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

pub async fn auth(
    stream: TcpStream,
    b_signing_key: [u8; 32],
    b_verifying_key: [u8; 32],
) -> Result<messaging::Protocol, Error> {
    let mut proto = signed::Protocol::new(stream, b_signing_key, b_verifying_key)?;

    let dh_secret = EphemeralSecret::random();
    let dh_public = PublicKey::from(&dh_secret);
    proto.send(dh_public.as_ref()).await?;

    let b_dh_peer_public = proto.receive().await?;
    let b_dh_peer_public: [u8; 32] = b_dh_peer_public.try_into()
        .map_err(|_| Error::InvalidResponse("peer public has wrong size".to_owned()))?;
    let dh_peer_public = PublicKey::from(b_dh_peer_public);

    let shared_secret = dh_secret.diffie_hellman(&dh_peer_public);

    let kdf = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
    let mut auth_key = [0; 32];
    kdf.expand(&[], &mut auth_key)?;

    let stream = proto.destruct();
    Ok(messaging::Protocol::new(stream, auth_key))
}
