# Secure Peer Protocol (SPP)

## Description

Chat with friends in a truly cryptographically secure way.

Intended to work as 5th OSI layer usually on top of TCP/IP.

[Python version](https://github.com/lifr0m/spproto)

### Mechanism

1. You and friend exchanged Ed25519 public keys through reliable way.
2. Shared key is obtained using X25519. X25519 public keys are 
   signed and verified using Ed25519.
3. Auth key is derived from shared key using SSKDF.
4. Messaging using auth key with ChaCha20-Poly1305.

### TODO

1. Key rotation

## Preparation before using

1. Generate private key, give your public key to friend.
2. Get friend's public key through reliable channel.

See `examples/generate_key_pair.rs`.

## How to use

### Client

Connect to your friend.

See `examples/client.rs`.

### Server

Make your friend available to connect to you.

See `examples/server.rs`.
