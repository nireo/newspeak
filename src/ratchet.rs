use anyhow::{Result, anyhow};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadMut, Payload},
};
use x25519_dalek as ecdh;
use x25519_dalek as x25519;

pub struct RatchetState {
    pub sending_sk: ecdh::StaticSecret,
    pub sending_pk: ecdh::PublicKey,
    pub receiving_pk: Option<ecdh::PublicKey>,
    pub receiving_counter: u64,
    pub sending_counter: u64,

    pub root_key: [u8; 32],
    pub chain_key_sending: [u8; 32],
    pub chain_key_receiving: [u8; 32],
}

pub struct RatchetMessageHeader {
    pub pk: ecdh::PublicKey,
    pub counter: u64,
    pub nonce: [u8; 12],
}

pub struct RatchetMessage {
    pub header: RatchetMessageHeader,
    pub ciphertext: Vec<u8>,
}

impl RatchetState {
    pub fn new() -> RatchetState {
        let mut rng = rand::thread_rng();
        let sending_sk = ecdh::StaticSecret::random_from_rng(&mut rng);
        let sending_pk = ecdh::PublicKey::from(&sending_sk);

        RatchetState {
            sending_sk,
            sending_pk,
            receiving_pk: None,
            receiving_counter: 0,
            sending_counter: 0,
            root_key: [0u8; 32],
            chain_key_sending: [0u8; 32],
            chain_key_receiving: [0u8; 32],
        }
    }

    pub fn as_initiator(&mut self, shared_key: [u8; 32], other_pk: ecdh::PublicKey) {
        self.receiving_pk = Some(other_pk);

        (self.root_key, self.chain_key_sending) = kdf_root_key(
            &shared_key,
            self.sending_sk.diffie_hellman(&self.receiving_pk.unwrap()), // unwrap fine since we
                                                                         // set the value above
        )
    }

    pub fn as_receiver(&mut self, shared_key: [u8; 32]) {
        self.root_key = shared_key;
    }

    pub fn send_message(
        &mut self,
        message: &str,
        aditionnal_data: &[u8],
    ) -> Result<RatchetMessage> {
        // state.CKs, mk = KDF_CK(state.CKs)
        let (new_chain_key_sending, message_key) = kdf_chain_key(&self.chain_key_sending);
        self.chain_key_sending = new_chain_key_sending;

        // here it's safe to use a 96-bit random nonce as each message is encrypted with a different key
        let nonce: [u8; 12] = rand::random();

        // header = HEADER(state.DHs, state.PN, state.Ns)
        let header = RatchetMessageHeader {
            pk: self.sending_pk,
            counter: self.sending_counter,
            nonce,
        };

        // ENCRYPT(mk, plaintext, AD || header)
        let mut cipher = ChaCha20Poly1305::new(&message_key.try_into()?);
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: message.as_bytes(),
                    aad: aditionnal_data,
                },
            )
            .map_err(|e| anyhow!("failed to encrypt message: {}", e.to_string()))?;

        let message = RatchetMessage { header, ciphertext };
        self.sending_counter += 1;

        Ok(message)
    }

    pub fn receive_message(
        &mut self,
        message: RatchetMessage,
        aditionnal_data: &[u8],
    ) -> Result<String> {
        if self.receiving_pk != Some(message.header.pk) {
            // state.DHr = header.dh
            self.receiving_pk = Some(message.header.pk);

            // state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
            (self.root_key, self.chain_key_receiving) = kdf_root_key(
                &self.root_key,
                self.sending_sk.diffie_hellman(&self.receiving_pk.unwrap()),
            );

            // generate a new Diffie-Hellman keypair
            // state.DHs = GENERATE_DH()
            self.sending_sk = x25519::StaticSecret::random_from_rng(&mut rand::thread_rng());
            self.sending_pk = x25519::PublicKey::from(&self.sending_sk);

            // state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
            (self.root_key, self.chain_key_sending) = kdf_root_key(
                &self.root_key,
                self.sending_sk.diffie_hellman(&self.receiving_pk.unwrap()),
            );
        }

        // state.CKr, mk = KDF_CK(state.CKr)
        let (chain_key_receiving, message_key) = kdf_chain_key(&self.chain_key_receiving);
        self.chain_key_receiving = chain_key_receiving;

        //  DECRYPT(mk, ciphertext, CONCAT(AD, header))
        let mut cipher = ChaCha20Poly1305::new(&message_key.try_into()?);
        let plaintext = cipher
            .decrypt(
                (&message.header.nonce).into(),
                Payload {
                    msg: &message.ciphertext,
                    aad: aditionnal_data,
                },
            )
            .map_err(|e| anyhow!("failed to decrypt message: {}", e.to_string()))?;

        let message_plaintext = String::from_utf8(plaintext)?;
        self.receiving_counter += 1;

        Ok(message_plaintext)
    }
}

fn kdf_root_key(key: &[u8; 32], shared_secret: ecdh::SharedSecret) -> ([u8; 32], [u8; 32]) {
    let mut kdf = blake3::Hasher::new_derive_key("DOUBLE_RATCHET_KDF_ROOT_KEY");
    kdf.update(key);
    kdf.update(shared_secret.as_bytes());
    let mut xof = kdf.finalize_xof();

    let mut root_key = [0u8; 32];
    xof.fill(&mut root_key);

    let mut chain_key = [0u8; 32];
    xof.fill(&mut chain_key);

    return (root_key, chain_key);
}

// input: chain_key
// output: (chain_key, message_key)
fn kdf_chain_key(key: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut kdf = blake3::Hasher::new_derive_key("DOUBLE_RATCHET_KDF_CHAIN_KEY");
    kdf.update(key);
    let mut xof = kdf.finalize_xof();

    let mut chain_key = [0u8; 32];
    xof.fill(&mut chain_key);

    let mut message_key = [0u8; 32];
    xof.fill(&mut message_key);

    return (chain_key, message_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet_allows_initiator_to_send_and_receiver_to_decrypt() {
        let shared_key: [u8; 32] = rand::random();
        let mut alice = RatchetState::new();
        let mut bob = RatchetState::new();

        let bob_pk = ecdh::PublicKey::from(&bob.sending_sk);
        alice.as_initiator(shared_key, bob_pk);
        bob.as_receiver(shared_key);

        let ad = b"header-data";
        let message = alice.send_message("hello", ad).unwrap();

        assert_eq!(alice.sending_counter, 1);
        assert_eq!(bob.receiving_counter, 0);

        bob.receive_message(message, ad).unwrap();

        assert_eq!(bob.receiving_counter, 1);
        assert_eq!(bob.receiving_pk, Some(alice.sending_pk));
    }

    #[test]
    fn ratchet_allows_bidirectional_messages() {
        let shared_key: [u8; 32] = rand::random();
        let mut alice = RatchetState::new();
        let mut bob = RatchetState::new();

        let bob_initial_pk = ecdh::PublicKey::from(&bob.sending_sk);
        alice.as_initiator(shared_key, bob_initial_pk);
        bob.as_receiver(shared_key);

        let ad = b"ratchet-ad";
        let to_bob = alice.send_message("ping", ad).unwrap();
        bob.receive_message(to_bob, ad).unwrap();

        let bob_reply_pk = ecdh::PublicKey::from(&bob.sending_sk);
        let to_alice = bob.send_message("pong", ad).unwrap();
        alice.receive_message(to_alice, ad).unwrap();

        assert_eq!(alice.receiving_pk, Some(bob_reply_pk));
        assert_eq!(alice.receiving_counter, 1);
        assert_eq!(bob.sending_counter, 1);
        assert_eq!(bob.receiving_counter, 1);
    }

    #[test]
    #[should_panic]
    fn ratchet_rejects_message_with_wrong_additional_data() {
        let shared_key: [u8; 32] = rand::random();
        let mut alice = RatchetState::new();
        let mut bob = RatchetState::new();

        let bob_pk = ecdh::PublicKey::from(&bob.sending_sk);
        alice.as_initiator(shared_key, bob_pk);
        bob.as_receiver(shared_key);

        let message = alice.send_message("secret", b"correct-ad").unwrap();
        bob.receive_message(message, b"incorrect-ad").unwrap();
    }
}
