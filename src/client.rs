use crate::{
    newspeak::{
        self, AddSignedPrekeysRequest, ClientMessage, FetchPrekeyBundleRequest, InitialMessage,
        JoinRequest, KeyKind, RatchetMessage as ProtoRatchetMessage, RegisterRequest,
        ServerMessage, client_message, newspeak_client::NewspeakClient, server_message,
    },
    pqxdh::{
        self, KeyExchangeUser, PQXDHInitMessage, PrekeyBundle, PublicSignedMlKemPrekey,
        PublicSignedPrekey,
    },
    ratchet::{self, RatchetMessage, RatchetState},
};
use anyhow::{Error, Result, anyhow};
use chrono::{DateTime, Local};
use ed25519_dalek::{self as ed25519, Signer};
use ml_kem::{Encoded, EncodedSizeUser, MlKem1024Params, kem::EncapsulationKey};
use prost_types::Timestamp;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use x25519_dalek as x25519;

mod tui;

/// User represents a client user with associated key info and gRPC client.
struct User<'a> {
    username: &'a str,
    key_info: Arc<Mutex<KeyExchangeUser>>,
    client: NewspeakClient<Channel>,
    auth_challenge: Option<[u8; 32]>,
}

impl From<&pqxdh::SignedPrekey> for newspeak::SignedPrekey {
    fn from(k: &pqxdh::SignedPrekey) -> Self {
        newspeak::SignedPrekey {
            kind: KeyKind::X25519.into(),
            key: k.public_key.as_bytes().to_vec(),
            signature: k.signature.to_vec(),
            id: 0,
        }
    }
}

impl From<&pqxdh::SignedMlKemPrekey> for newspeak::SignedPrekey {
    fn from(k: &pqxdh::SignedMlKemPrekey) -> Self {
        newspeak::SignedPrekey {
            kind: KeyKind::MlKem1024.into(),
            key: k.encap_key.as_bytes().as_slice().to_vec(),
            signature: k.signature.to_vec(),
            id: 0,
        }
    }
}

fn signed_prekey_with_id(id: u32, key: &pqxdh::SignedPrekey) -> newspeak::SignedPrekey {
    let mut prekey: newspeak::SignedPrekey = key.into();
    prekey.id = id;
    prekey
}

impl<'a> User<'a> {
    pub fn new(
        username: &'a str,
        client: NewspeakClient<Channel>,
        key_info: KeyExchangeUser,
    ) -> Self {
        User {
            username,
            key_info: Arc::new(Mutex::new(key_info)),
            client,
            auth_challenge: None,
        }
    }

    /// register sends the registration request to the server and processes the response.
    /// It also adds any unused one-time prekeys to the server.
    pub async fn register(&mut self) -> Result<()> {
        let (identity_key, signed_prekey, kem_prekey, one_time_prekeys, kem_prekeys) = {
            let key_info = self.key_info.lock().await;
            let one_time_prekeys = key_info
                .one_time_keys
                .iter()
                .filter_map(|(id, key, used)| {
                    if used {
                        None
                    } else {
                        Some(signed_prekey_with_id(*id, key))
                    }
                })
                .collect::<Vec<_>>();
            let kem_prekeys = key_info
                .one_time_kem_keys
                .iter()
                .filter_map(|(_, key, used)| if used { None } else { Some(key.into()) })
                .collect::<Vec<_>>();
            (
                key_info.identity_pk.as_bytes().to_vec(),
                (&key_info.signed_prekey).into(),
                (&key_info.last_resort_kem).into(),
                one_time_prekeys,
                kem_prekeys,
            )
        };

        let req = RegisterRequest {
            username: self.username.into(),
            identity_key,
            signed_prekey: Some(signed_prekey),
            one_time_prekeys,
            kem_prekey: Some(kem_prekey),
        };

        let response = self.client.register(req).await?.into_inner();
        let challenge: [u8; 32] = response.auth_challenge.as_slice().try_into().map_err(|_| {
            anyhow!(
                "invalid auth challenge length: {}",
                response.auth_challenge.len()
            )
        })?;

        self.auth_challenge = Some(challenge);
        if !kem_prekeys.is_empty() {
            self.client
                .add_signed_prekeys(AddSignedPrekeysRequest {
                    keys: kem_prekeys,
                    username: self.username.into(),
                })
                .await?;
        }

        Ok(())
    }

    /// sign_auth_challenge signs the stored authentication challenge using the user's identity
    /// signing key. This allows authentication without having to store passwords on the server.
    pub async fn sign_auth_challenge(&self) -> Result<Vec<u8>> {
        let challenge = self
            .auth_challenge
            .ok_or_else(|| anyhow!("missing auth challenge; register first"))?;

        let key_info = self.key_info.lock().await;
        let signature = key_info.identity_sk.sign(&challenge);
        Ok(signature.to_bytes().to_vec())
    }

    /// create_key_exchange_message creates a key exchange message to initiate a conversation with
    /// some other user. It fetches their prekey bundle from the server and then constructs a
    /// shared secret and initial message using local keys and the given prekey bundle keys.
    pub async fn create_key_exchange_message(
        &mut self,
        other: String,
    ) -> Result<(newspeak::KeyExchangeMessage, RatchetState, [u8; 32])> {
        let receiver_id = other.clone();
        let response = self
            .client
            .fetch_prekey_bundle(FetchPrekeyBundleRequest { username: other })
            .await?
            .into_inner();

        let bundle = response
            .bundle
            .ok_or_else(|| anyhow!("missing prekey bundle in response"))?;
        let prekey_bundle: PrekeyBundle = (&bundle).try_into()?;
        let peer_identity = *prekey_bundle.identity_pk.as_bytes();
        let key_info = self.key_info.lock().await;
        let init_output = key_info.init_key_exchange(&prekey_bundle)?;
        let init_message = init_output.message;

        let ratchet_state = RatchetState::as_initiator(
            init_output.secret_key,
            prekey_bundle.signed_prekey.public_key,
        );

        // the initial message contains all information that the receiver needs to complete the key
        // exchange and end up with the same shared secret.
        let initial_message = newspeak::InitialMessage {
            identity_key: init_message.peer_identity_public_key.as_bytes().to_vec(),
            ephemeral_key: init_message.ephemeral_x25519_public_key.as_bytes().to_vec(),
            kem_ciphertext: init_message.mlkem_ciphertext.to_vec(),
            one_time_prekey_id: init_message.one_time_prekey_used,
            kem_id: init_message.kem_used.to_vec(),
        };

        Ok((
            newspeak::KeyExchangeMessage {
                sender_id: self.username.to_string(),
                receiver_id,
                initial_message: Some(initial_message),
                timestamp: None,
            },
            ratchet_state,
            peer_identity,
        ))
    }

    /// send_join_request sends a join request to the server with the user's signed authentication
    /// challenge.
    async fn send_join_request(&self, tx: &mpsc::Sender<ClientMessage>) -> Result<()> {
        let auth_signature = self.sign_auth_challenge().await?;
        tx.send(ClientMessage {
            message_type: Some(client_message::MessageType::JoinRequest(JoinRequest {
                username: self.username.to_string(),
                signature: auth_signature,
            })),
        })
        .await?;
        Ok(())
    }

    async fn setup_message_stream(
        &self,
    ) -> Result<(mpsc::Sender<ClientMessage>, tonic::Streaming<ServerMessage>)> {
        let (tx, rx) = mpsc::channel(32);
        let response = self
            .client
            .clone()
            .message_stream(ReceiverStream::new(rx))
            .await?;

        Ok((tx, response.into_inner()))
    }
}

impl TryFrom<&newspeak::PrekeyBundle> for PrekeyBundle {
    type Error = Error;

    fn try_from(bundle: &newspeak::PrekeyBundle) -> std::result::Result<Self, Self::Error> {
        let identity_key = ed25519::VerifyingKey::try_from(bundle.identity_key.as_slice())
            .map_err(|err| anyhow!("invalid ed25519 public key: {}", err))?;

        let signed_prekey = bundle
            .signed_prekey
            .as_ref()
            .ok_or_else(|| anyhow!("missing signed_prekey in bundle"))?;
        let signed_prekey: PublicSignedPrekey = signed_prekey.try_into()?;

        let kem_encap_key = bundle
            .kem_encap_key
            .as_ref()
            .ok_or_else(|| anyhow!("missing kem_encap_key in bundle"))?;
        let kem_encap_key: PublicSignedMlKemPrekey = kem_encap_key.try_into()?;

        let one_time_prekey = bundle
            .one_time_prekey
            .as_ref()
            .map(TryInto::try_into)
            .transpose()?;

        let kem_id: [u8; 16] = bundle
            .kem_id
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid kem_id length: {}", bundle.kem_id.len()))?;

        Ok(PrekeyBundle::new(
            signed_prekey,
            kem_encap_key,
            identity_key,
            one_time_prekey,
            bundle.one_time_prekey_id,
            kem_id,
        ))
    }
}

impl TryFrom<&newspeak::SignedPrekey> for PublicSignedPrekey {
    type Error = Error;

    fn try_from(prekey: &newspeak::SignedPrekey) -> Result<Self> {
        let kind = KeyKind::try_from(prekey.kind)
            .map_err(|_| anyhow!("unknown key kind {}", prekey.kind))?;
        if kind != KeyKind::X25519 {
            return Err(anyhow!("expected x25519 signed prekey"));
        }

        let public_key_bytes: [u8; 32] = prekey
            .key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid x25519 public key length: {}", prekey.key.len()))?;
        let signature = ed25519::Signature::try_from(prekey.signature.as_slice())
            .map_err(|err| anyhow!("invalid ed25519 signature: {}", err))?;

        Ok(PublicSignedPrekey {
            public_key: x25519::PublicKey::from(public_key_bytes),
            signature,
        })
    }
}

impl TryFrom<&newspeak::SignedPrekey> for PublicSignedMlKemPrekey {
    type Error = Error;

    fn try_from(prekey: &newspeak::SignedPrekey) -> Result<Self> {
        let kind = KeyKind::try_from(prekey.kind)
            .map_err(|_| anyhow!("unknown key kind {}", prekey.kind))?;
        if kind != KeyKind::MlKem1024 {
            return Err(anyhow!("expected ML-KEM-1024 signed prekey"));
        }

        let encoded = Encoded::<EncapsulationKey<MlKem1024Params>>::try_from(prekey.key.as_slice())
            .map_err(|_| {
                anyhow!(
                    "invalid ML-KEM encapsulation key length: {}",
                    prekey.key.len()
                )
            })?;
        let signature = ed25519::Signature::try_from(prekey.signature.as_slice())
            .map_err(|err| anyhow!("invalid ed25519 signature: {}", err))?;

        Ok(PublicSignedMlKemPrekey {
            encap_key: EncapsulationKey::from_bytes(&encoded),
            signature,
        })
    }
}

impl From<ratchet::RatchetMessage> for ProtoRatchetMessage {
    fn from(message: ratchet::RatchetMessage) -> Self {
        ProtoRatchetMessage {
            public_key: message.header.pk.as_bytes().to_vec(),
            previous_chain_length: 0,
            message_number: message.header.counter as i32,
            ciphertext: message.ciphertext,
            nonce: message.header.nonce.to_vec(),
        }
    }
}

impl TryFrom<ProtoRatchetMessage> for RatchetMessage {
    type Error = Error;

    fn try_from(message: ProtoRatchetMessage) -> Result<Self> {
        let public_key_bytes: [u8; 32] =
            message.public_key.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "invalid x25519 public key length: {}",
                    message.public_key.len()
                )
            })?;
        let nonce: [u8; 12] = message
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid ratchet nonce length: {}", message.nonce.len()))?;
        let counter: u64 = message
            .message_number
            .try_into()
            .map_err(|_| anyhow!("invalid ratchet message counter"))?;

        Ok(RatchetMessage {
            header: ratchet::RatchetMessageHeader {
                pk: x25519::PublicKey::from(public_key_bytes),
                counter,
                nonce,
            },
            ciphertext: message.ciphertext,
        })
    }
}

impl TryFrom<&InitialMessage> for PQXDHInitMessage {
    type Error = Error;

    fn try_from(message: &InitialMessage) -> Result<Self> {
        let peer_identity_public_key =
            ed25519::VerifyingKey::try_from(message.identity_key.as_slice())
                .map_err(|err| anyhow!("invalid ed25519 public key: {}", err))?;
        let ephemeral_key_bytes: [u8; 32] =
            message.ephemeral_key.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "invalid x25519 public key length: {}",
                    message.ephemeral_key.len()
                )
            })?;
        let kem_used: [u8; 16] = message
            .kem_id
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid kem_id length: {}", message.kem_id.len()))?;

        Ok(PQXDHInitMessage {
            peer_identity_public_key,
            ephemeral_x25519_public_key: x25519::PublicKey::from(ephemeral_key_bytes),
            mlkem_ciphertext: message.kem_ciphertext.clone(),
            kem_used,
            one_time_prekey_used: message.one_time_prekey_id,
        })
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn timestamp_seconds(timestamp: Option<&Timestamp>) -> i64 {
    timestamp
        .map(|t| t.seconds)
        .unwrap_or_else(now_unix_seconds)
}

fn format_timestamp(timestamp: i64) -> String {
    if timestamp <= 0 {
        return "unknown time".to_string();
    }

    let system_time = UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64);
    let datetime: DateTime<Local> = system_time.into();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn is_newer_timestamp(candidate: &Timestamp, current: &Timestamp) -> bool {
    (candidate.seconds, candidate.nanos) > (current.seconds, current.nanos)
}

fn server_message_from_client_message(message: ClientMessage) -> Option<ServerMessage> {
    match message.message_type {
        Some(client_message::MessageType::KeyExchangeMessage(inner)) => Some(ServerMessage {
            message_type: Some(server_message::MessageType::KeyExchange(inner)),
        }),
        Some(client_message::MessageType::EncryptedMessage(inner)) => Some(ServerMessage {
            message_type: Some(server_message::MessageType::Encrypted(inner)),
        }),
        _ => None,
    }
}

const RATCHET_AAD_DOMAIN: &[u8] = b"newspeak-ratchet-aad-v1";

// Bind message metadata to the AEAD to prevent in-transit tampering.
fn ratchet_aad(sender_id: &str, receiver_id: &str) -> Vec<u8> {
    let sender_len = sender_id.len() as u32;
    let receiver_len = receiver_id.len() as u32;
    let mut aad = Vec::with_capacity(
        RATCHET_AAD_DOMAIN.len() + 1 + 4 + sender_id.len() + 4 + receiver_id.len(),
    );
    aad.extend_from_slice(RATCHET_AAD_DOMAIN);
    aad.push(0);
    aad.extend_from_slice(&sender_len.to_le_bytes());
    aad.extend_from_slice(sender_id.as_bytes());
    aad.extend_from_slice(&receiver_len.to_le_bytes());
    aad.extend_from_slice(receiver_id.as_bytes());
    aad
}

fn parse_args() -> Result<(String, Option<String>)> {
    let mut positional = Vec::new();

    for arg in std::env::args().skip(1) {
        positional.push(arg);
    }

    if positional.is_empty() {
        return Err(anyhow!("usage: newspeak <you> [optional username]"));
    }

    Ok((positional[0].clone(), positional.get(1).cloned()))
}

pub async fn run() -> Result<()> {
    let (username, receiver_arg) = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            println!("{}", err);
            std::process::exit(1);
        }
    };

    tui::run(username, receiver_arg).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receiver(shared_key: [u8; 32]) -> RatchetState {
        let sending_sk = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        RatchetState::as_receiver(shared_key, sending_sk)
    }

    #[test]
    fn ratchet_aad_allows_valid_metadata() {
        let shared_key: [u8; 32] = rand::random();
        let mut bob = receiver(shared_key);
        let bob_pk = x25519::PublicKey::from(&bob.sending_sk);
        let mut alice = RatchetState::as_initiator(shared_key, bob_pk);

        let aad = ratchet_aad("alice", "bob");
        let message = alice.send_message("hello", &aad).unwrap();

        let plaintext = bob.receive_message(message, &aad).unwrap();
        assert_eq!(plaintext, "hello");
    }

    #[test]
    fn ratchet_aad_rejects_mismatched_metadata() {
        let shared_key: [u8; 32] = rand::random();
        let mut bob = receiver(shared_key);
        let bob_pk = x25519::PublicKey::from(&bob.sending_sk);
        let mut alice = RatchetState::as_initiator(shared_key, bob_pk);

        let aad = ratchet_aad("alice", "bob");
        let message = alice.send_message("secret", &aad).unwrap();

        let wrong_aad = ratchet_aad("alice", "carol");
        assert!(bob.receive_message(message, &wrong_aad).is_err());
    }
}
