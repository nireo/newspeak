# newspeak

A end-to-end encrypted chat application with a terminal interface. It uses the Post-Quantum Extended Diffie-Hellman protocol by Signal for key exchange. Currently the message encryption itself is implemented using the double ratchet algorithm which is insecure against quantum computers, and a transition to the triple ratchet algorithm is the works.

This is basically a Rust rewrite of my Go e2e chat application project [pch](https://github.com/nireo/pch) that was pretty much similar.

## Architecture

Here is quick description of the server and client, their responsibilities and how they're built.

### Server

The server is a gRPC server written using [tonic](https://github.com/hyperium/tonic) and the public key information is stored in a sqlite database. The role of the server is to transport public keys between parties, as in Signal's protocol, there is nothing stopping the server from theoretically being a man-in-the-middle and sending its own keys to parties. This is not a problem this application looks to solve, rather the identity key of the person should be verified via a different channel. The only kind of cryptography the server performs is verifying some user signatures using the user's identity key.

When talking about keys here, they're obviously public as the server doesn't receive any private keys. The server stores for each user: identity key, signed prekey, last resort KEM key, multiple one-time signed EC prekeys and KEM keys. To provide the best security the one-time keys should be used in the key exchange process. The server also takes care of having active streams to stream messages in real-time if both parties are online, and storing the encrypted messages that are sent when the receiver is offline.

The server can be started using:

```ssh
$ cargo run --bin server
```

### Client

The client is responsible for the cryptography. Client creates a shared secret with the local keys combined with the prekey bundle received from the server. Once the initiator is finished with the key generation, they send a key exchange message to the server that the server sends to the receiver. The message contains everything to create the shared secret. The shared secret is then fed into the double ratchet implementation which continuously updates keys between messages to keep the process secure even if keys are compromised. Please check Signal's website for information about both [PQXDH](https://signal.org/docs/specifications/pqxdh/) and [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/).
