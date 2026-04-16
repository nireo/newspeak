# newspeak

`newspeak` is an end-to-end encrypted terminal chat application written in Rust. It uses Signal's [PQXDH](https://signal.org/docs/specifications/pqxdh/) protocol for key agreement and a [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) implementation for message encryption. The initial key agreement is post-quantum, but the message layer is still Double Ratchet, so the project is not yet fully post-quantum end-to-end. Signal has published documents detailing a post-quantum Triple Ratchet design, but that has not yet been implemented here.

This is a Rust rewrite of my earlier Go project [pch](https://github.com/nireo/pch), mainly to experiment with using Rust for cryptography work.

## Architecture

### Server

The server is a gRPC service built with [tonic](https://github.com/hyperium/tonic). It listens on `[::1]:10000` and stores server-side state in `server_newspeak.db`.

The server stores only public or relayable data. In practice that means each user's identity key, signed X25519 prekey, last-resort ML-KEM prekey, batches of one-time X25519 and ML-KEM keys, and any encrypted offline messages waiting to be delivered.

The server does not participate in end-to-end encryption beyond verifying signatures that prove control of a user's long-term identity key. That same identity key is also used to sign the server's authentication challenge when a client joins the live message stream, which lets the server authenticate the connection without keeping a password database. Even with that check, the server can still theoretically act as a man-in-the-middle when distributing identity keys and prekey bundles, so peer identity verification still has to happen out of band. That is the same basic trust model Signal uses.

When a recipient is offline, the server stores encrypted messages and pending key exchange messages and delivers them when that user joins again. Once the client acknowledges receipt of those offline messages, the server deletes them.

Start the server with:

```sh
cargo run --bin server
```

### Client

The client is responsible for all cryptographic operations and presents a terminal UI built with `ratatui`. On startup it connects to `http://[::1]:10000`, creates or opens `<username>_newspeak.db`, loads or generates the local identity key and prekeys, registers its public key material with the server, joins the streaming message channel, and replays any offline messages returned by the server. Each client database stores the private key material, peer identities, ratchet state, and local message history for that username.

Run a client with:

```sh
cargo run --bin client -- alice
```

You can pass an optional second username to immediately open that conversation. After the client joins the stream, it will also attempt to initialize the key exchange for that peer if no ratchet state exists yet.

```sh
cargo run --bin client -- alice bob
```

## Cryptography

`newspeak` splits its cryptography into two phases. The first phase establishes a shared secret between two users who may not be online at the same time. The second phase turns that shared secret into per-message keys that keep changing as the conversation continues. That split is important because the initial handshake and the ongoing message protection solve different problems.

Each user has a long-term Ed25519 identity key that acts as the stable identity for that account. The client uses that identity key to sign the public prekeys it uploads to the server. Those prekeys currently include a signed X25519 prekey, a signed ML-KEM-1024 last-resort key, and batches of one-time X25519 and ML-KEM keys. The private halves of those keys stay in the local client database. When one user starts a conversation with another, the initiating client fetches the receiver's prekey bundle from the server and first verifies that the signed X25519 and ML-KEM keys in that bundle were really signed by the receiver's identity key. That check prevents a simple substitution of unsigned prekeys, but it does not by itself prove that the server handed out the correct identity key in the first place, which is why manual identity verification is still necessary.

After the bundle has been checked, the initiator creates a fresh ephemeral X25519 key and performs the PQXDH calculation. In this implementation the Ed25519 identity keys are converted into their X25519 form for the Diffie-Hellman parts of the handshake. The server may hand out a one-time ML-KEM key if one is available, or fall back to the receiver's last-resort ML-KEM key if it is not. The resulting shared secret is built from several independent pieces at once, so breaking any single one of them is not enough to reconstruct the whole handshake.

```text
Let A be the initiator and B the receiver.

IKA = A's identity key, converted to X25519 for DH
IKB = B's identity key, converted to X25519 for DH
EKA = A's fresh ephemeral X25519 key
SPKB = B's signed X25519 prekey
OPKB = B's one-time X25519 prekey, if present
KEMB = B's one-time ML-KEM key, or B's last-resort ML-KEM key

DH1 = DH(IKA, SPKB)
DH2 = DH(EKA, IKB)
DH3 = DH(EKA, SPKB)
DH4 = DH(EKA, OPKB)            // only when a one-time prekey is available

(ct, ss) = ML-KEM-1024.Encaps(KEMB)

SK = SHAKE256(
    0xff repeated 32 times ||
    DH1 || DH2 || DH3 || [DH4] || ss ||
    "PQXDH_CURVE25519_SHAKE256_ML-KEM-1024"
)
```

The public handshake message sent to the receiver contains the initiator's identity public key, the ephemeral X25519 public key, the ML-KEM ciphertext, and the identifiers that tell the receiver which optional one-time keys were used. The receiver uses that public message together with its own private keys to recompute the same components and derive the same `SK` locally.

That shared secret is then used to seed the Double Ratchet state for the conversation. From that point on, the application does not keep reusing one static session key. Instead, each outgoing message advances the current sending chain and derives a fresh message key, so the key used for one message is distinct from the key used for the next. Messages are encrypted with ChaCha20-Poly1305. The implementation also authenticates associated data that binds the sender username, receiver username, ratchet public key, message counter, and nonce to the ciphertext. If any of that metadata is changed in transit, decryption fails. When a new ratchet public key arrives from the peer, the receiver performs a new Diffie-Hellman ratchet step, refreshes the root key, and derives new sending and receiving chains. The code also keeps a bounded cache of skipped message keys so that a small amount of out-of-order delivery can still be decrypted safely.

```text
Initial setup:

Initiator:
    (RK, CKs) = KDF_RK(SK, DH(DHs, DHr))

Receiver:
    RK = SK
    // receiving and sending chains are derived on the first ratchet step

Per message:

    (CKs', MK) = KDF_CK(CKs)
    header      = (ratchet_public_key, message_counter, nonce)
    aad         = sender_id || receiver_id || header
    ciphertext  = ChaCha20-Poly1305_Encrypt(MK, plaintext, aad)

On a new peer ratchet key:

    (RK, CKr) = KDF_RK(RK, DH(current_local_dh_sk, new_remote_dh_pk))
    generate fresh local DH key pair
    (RK, CKs) = KDF_RK(RK, DH(new_local_dh_sk, new_remote_dh_pk))
```

## Running Locally

1. Start the server in one terminal:

   ```sh
   cargo run --bin server
   ```

2. Start two clients in separate terminals:

   ```sh
   cargo run --bin client -- alice
   cargo run --bin client -- bob
   ```

3. In one of the clients, start a conversation:

   ```text
   /init bob
   ```

4. In the other client, either run `/init alice`, run `/switch alice`, or select the conversation from the sidebar.

5. Once the key exchange completes, type messages and press `Enter` to send.

## TUI Commands

Use `/init <username>` to open a conversation and perform the key exchange when no ratchet state exists yet. Use `/switch <username>` to move to an existing conversation. Use `/verify` to mark the active peer as manually verified in local storage. Use `/help` to print the available commands in the chat view, and use `/quit` to exit the client.

## TUI Controls

Use `Up` and `Down` to move through the conversation list, and press `Tab` to open the selected conversation. Press `Enter` to send the current input, or to open the selected conversation when the input field is empty. Press `Esc` to clear the current input, or to quit if the input is already empty. Press `Ctrl+C` to quit immediately.

## Verification Number

When a new peer identity is seen, the client prints a verification number in the chat view. This is a human-readable fingerprint of the two long-term identity keys in the conversation. It is not derived from the current ratchet state, from recent messages, or from any temporary session value. Instead, the client takes the local identity public key and the peer identity public key, sorts them into a canonical order so that both sides hash the same pair in the same order, prepends a domain label, hashes the result with SHA3-256, and formats part of that hash as ten groups of five digits. Because both users are hashing the same two identity keys, they should see the same verification number when no substitution has happened.

```text
first, second = sort_lexicographically(local_identity_pk, peer_identity_pk)

digest = SHA3-256(
    "newspeak-safety-v1" || first || second
)

for i in 0..9:
    group_i = little_endian_u16(digest[2*i : 2*i+2])
    print group_i as a zero-padded 5-digit number

verification_number =
    g0 g1 g2 g3 g4 g5 g6 g7 g8 g9
```

The purpose of that number is to let two humans compare identities over a separate trusted channel such as in person, over voice, or through some other already-authenticated medium. If Alice and Bob see different numbers, they do not have the same view of the conversation identities, which means the session should not be trusted. If they see the same number, they have strong evidence that the identity keys at both ends match.

The `/verify` command does not contact the server, does not notify the other party, and does not add a new cryptographic step to the protocol. It only records in local storage that you have manually checked the current peer identity and decided to trust it. Because the verification number is tied to the long-term identity keys, it stays stable across new sessions with the same peer and only changes when one of those identity keys changes. In this codebase, if a stored peer identity later changes, the client treats that as an identity mismatch and refuses the key exchange instead of silently trusting the new key.

## Data Files

The server keeps its public-key and offline-message state in `server_newspeak.db`. Each client keeps its local state in `<username>_newspeak.db`, including private key material, stored peer identities, ratchet state, and local message history. Deleting those files is the easiest way to reset local test state.

## Quick Test Session

Use the helper script to reset the databases, start the server, and open two client instances in `tmux`:

```sh
./scripts/test-session.sh
```

This starts clients as `alice` and `bob` by default. You can override the usernames:

```sh
./scripts/test-session.sh charlie dana
```

The script deletes `server_newspeak.db`, `<user A>_newspeak.db`, and `<user B>_newspeak.db`, creates a tmux session named `newspeak-test`, opens three windows named `server`, `<user A>`, and `<user B>`, and then attaches to the session automatically.

If you want a different tmux session name, set `SESSION_NAME`:

```sh
SESSION_NAME=my-newspeak ./scripts/test-session.sh
```

For the most predictable first-run flow, run `/init <other-user>` in both client windows after they start.
