use crate::protocols::{messaging, signed};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
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

pub struct Step1 {
    proto: signed::Protocol,
    dh_secret: EphemeralSecret,
}

pub fn step1(b_signing_key: [u8; 32], b_verifying_key: [u8; 32]) -> Result<(Vec<u8>, Step1), Error> {
    let proto = signed::Protocol::new(b_signing_key, b_verifying_key)?;

    let dh_secret = EphemeralSecret::random();
    let dh_public = PublicKey::from(&dh_secret);

    let msg = proto.pack(dh_public.as_ref())?;
    let step = Step1 { proto, dh_secret };

    Ok((msg, step))
}

pub fn step2(data: Step1, msg: &[u8]) -> Result<messaging::Protocol, Error> {
    let b_dh_peer_public = data.proto.unpack(msg)?;
    let b_dh_peer_public: [u8; 32] = b_dh_peer_public.try_into()
        .map_err(|_| Error::InvalidResponse("peer public has wrong size".to_string()))?;
    let dh_peer_public = PublicKey::from(b_dh_peer_public);

    let shared_secret = data.dh_secret.diffie_hellman(&dh_peer_public);

    let kdf = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
    let mut auth_key = [0; 32];
    kdf.expand(&[], &mut auth_key)?;

    log::debug!("auth key: {}", hex::encode(auth_key));
    Ok(messaging::Protocol::new(auth_key))
}
