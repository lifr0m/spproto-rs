use crate::protocols::{messaging, signed};
use aws_lc_rs::error::KeyRejected;
use aws_lc_rs::kdf::{get_sskdf_digest_algorithm, sskdf_digest, SskdfDigestAlgorithmId};
use aws_lc_rs::{agreement, rand, signature};
use thiserror::Error;
use tokio::net::TcpStream;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("error parsing key pair: {0}")]
    InvalidKeyPair(#[from] KeyRejected),

    #[error("internal error generating dh private key")]
    DhPrivateKeyGenerationFailed,

    #[error("internal error computing dh public key")]
    DhPublicKeyComputationFailed,

    #[error("signed transmit error: {0}")]
    SignedTransmitFailed(#[from] signed::TransmitError),

    #[error("dh agreement failed")]
    DhAgreementFailed,

    #[error("auth key derivation failed")]
    AuthKeyDerivationFailed,
}

pub async fn auth(
    stream: TcpStream,
    b_key_pair: Vec<u8>,
    b_peer_public_key: Vec<u8>,
) -> Result<messaging::MessagingProtocol, AuthError> {
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(&b_key_pair)?;
    let peer_public_key = signature::UnparsedPublicKey::new(
        &signature::ED25519, b_peer_public_key,
    );

    auth_impl(stream, key_pair, peer_public_key).await
}

async fn auth_impl(
    stream: TcpStream,
    key_pair: signature::Ed25519KeyPair,
    peer_public_key: signature::UnparsedPublicKey<Vec<u8>>,
) -> Result<messaging::MessagingProtocol, AuthError> {
    let mut proto = signed::SignedProtocol::new(
        stream, key_pair, peer_public_key,
    );

    let rng = rand::SystemRandom::new();
    let dh_private_key = agreement::EphemeralPrivateKey::generate(
        &agreement::X25519, &rng,
    ).map_err(|_| AuthError::DhPrivateKeyGenerationFailed)?;

    let dh_public_key = dh_private_key.compute_public_key()
        .map_err(|_| AuthError::DhPublicKeyComputationFailed)?;
    proto.send(dh_public_key.as_ref()).await?;

    let b_dh_peer_public_key = proto.receive().await?;
    let dh_peer_public_key = agreement::UnparsedPublicKey::new(
        &agreement::X25519, b_dh_peer_public_key,
    );

    let auth_key = agreement::agree_ephemeral(
        dh_private_key,
        &dh_peer_public_key,
        AuthError::DhAgreementFailed,
        |shared_key| {
            let algorithm = get_sskdf_digest_algorithm(SskdfDigestAlgorithmId::Sha256)
                .expect("wrong sskdf digest algorithm id");
            let mut auth_key = vec![0; 32];
            sskdf_digest(algorithm, shared_key, &[], &mut auth_key)
                .map_err(|_| AuthError::AuthKeyDerivationFailed)?;
            Ok(auth_key)
        },
    )?;

    let stream = proto.destruct();
    Ok(messaging::MessagingProtocol::new(stream, auth_key))
}
