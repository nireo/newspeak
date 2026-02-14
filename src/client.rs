use crate::{
    local_store::{LocalStorage, PeerIdentityStoreResult},
    newspeak::{
        self, AckOfflineMessages, AddSignedPrekeysRequest, ClientMessage, EncryptedMessage,
        FetchPrekeyBundleRequest, InitialMessage, JoinRequest, JoinResponse, KeyKind,
        RatchetMessage as ProtoRatchetMessage, RegisterRequest, ServerMessage, client_message,
        newspeak_client::NewspeakClient, server_message,
    },
    pqxdh::{
        self, KeyExchangeUser, PQXDHInitMessage, PrekeyBundle, PublicSignedMlKemPrekey,
        PublicSignedPrekey,
    },
    ratchet::{self, RatchetMessage, RatchetState},
    verification,
};
use anyhow::{Error, Result, anyhow};
use chrono::{DateTime, Local};
use ed25519_dalek::{self as ed25519, Signer};
use ml_kem::{Encoded, EncodedSizeUser, MlKem1024Params, kem::EncapsulationKey};
use prost_types::Timestamp;
use std::io::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use x25519_dalek as x25519;

type StdinLines = tokio::io::Lines<BufReader<io::Stdin>>;

/// ActiveConversation represents a conversation with some receiver and its associated ratchet
/// state.
struct ActiveConversation {
    receiver: Option<String>,
    ratchet_state: Option<RatchetState>,
}

impl ActiveConversation {
    fn new(receiver: Option<String>, ratchet_state: Option<RatchetState>) -> Self {
        Self {
            receiver,
            ratchet_state,
        }
    }
}

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
            init_output.secret_key.clone(),
            prekey_bundle.signed_prekey.public_key.clone(),
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

fn clear_terminal() {
    print!("\x1b[2J\x1b[H");
    let _ = std::io::stdout().flush();
}

fn print_incoming(message: &str) {
    print!("\r\x1b[2K");
    println!("{}", message);
    let _ = std::io::stdout().flush();
}

fn print_outgoing(message: &str) {
    // Replace the echoed input line with the formatted message.
    print!("\x1b[1A\r\x1b[2K");
    println!("{}", message);
    let _ = std::io::stdout().flush();
}

fn print_safety_number(peer: &str, safety_number: &str, verified: bool) {
    let timestamp = now_unix_seconds();
    let status = if verified { "verified" } else { "unverified" };
    print_incoming(&format_chat_line(
        timestamp,
        "system",
        &format!(
            "safety number with {} ({}): {}",
            peer, status, safety_number
        ),
    ));
    if !verified {
        print_incoming(&format_chat_line(
            timestamp,
            "system",
            "verify out-of-band and then run /verify",
        ));
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

fn format_chat_line(timestamp: i64, sender: &str, content: &str) -> String {
    format!("[{}] {}: {}", format_timestamp(timestamp), sender, content)
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

async fn handle_key_exchange_message(
    message: newspeak::KeyExchangeMessage,
    key_info: &Arc<Mutex<KeyExchangeUser>>,
    active_conversation: &Arc<Mutex<ActiveConversation>>,
    storage: &LocalStorage,
    username: &str,
) {
    let timestamp = timestamp_seconds(message.timestamp.as_ref());
    let Some(init_message) = message.initial_message.as_ref() else {
        eprintln!("missing initial message in key exchange");
        return;
    };

    let init = match PQXDHInitMessage::try_from(init_message) {
        Ok(init) => init,
        Err(err) => {
            eprintln!("failed to parse key exchange: {}", err);
            return;
        }
    };

    let (shared_key, sending_sk, one_time_prekey_used, kem_used, last_resort_id, local_identity) = {
        let mut key_info = key_info.lock().await;
        let shared_key = match key_info.receive_key_exchange(&init) {
            Ok(shared_key) => shared_key,
            Err(err) => {
                eprintln!("failed to receive key exchange: {}", err);
                return;
            }
        };
        let one_time_prekey_used = init.one_time_prekey_used;
        if let Some(id) = one_time_prekey_used {
            key_info.one_time_keys.mark_used(&id);
        }
        let kem_used = init.kem_used;
        if kem_used != key_info.last_resort_id {
            key_info.one_time_kem_keys.mark_used(&kem_used);
        }
        (
            shared_key,
            key_info.signed_prekey.private_key.clone(),
            one_time_prekey_used,
            kem_used,
            key_info.last_resort_id,
            key_info.identity_pk.to_bytes(),
        )
    };

    let peer_identity = init.peer_identity_public_key.to_bytes();
    let store_result = match storage
        .store_peer_identity(username, &message.sender_id, &peer_identity)
        .await
    {
        Ok(result) => result,
        Err(err) => {
            eprintln!("failed to store peer identity: {}", err);
            return;
        }
    };
    if matches!(store_result, PeerIdentityStoreResult::ExistingMismatch) {
        eprintln!(
            "identity key mismatch for {}; refusing to accept key exchange",
            message.sender_id
        );
        return;
    }
    let show_safety = match store_result {
        PeerIdentityStoreResult::Inserted => true,
        PeerIdentityStoreResult::ExistingMatch { verified } => !verified,
        PeerIdentityStoreResult::ExistingMismatch => false,
    };
    if show_safety {
        let safety_number = verification::safety_number_string(&local_identity, &peer_identity);
        print_safety_number(&message.sender_id, &safety_number, false);
    }

    // mark the keys separately not to hold the mutex down. it doesn't really matter though since
    // these are mainly local db operations which are really fast. just as a note. also makes sense
    // to copy the value out not to hold the guard for way too long.
    if let Some(id) = one_time_prekey_used {
        if let Err(err) = storage.mark_ec_key_used(username, id).await {
            eprintln!("failed to mark one-time prekey used: {}", err);
        }
    }

    if kem_used != last_resort_id {
        if let Err(err) = storage.mark_kem_key_used(username, &kem_used).await {
            eprintln!("failed to mark one-time kem key used: {}", err);
        }
    }

    let mut ratchet = RatchetState::as_receiver(shared_key);
    ratchet.sending_sk = sending_sk;
    ratchet.sending_pk = x25519::PublicKey::from(&ratchet.sending_sk);

    if let Err(err) = storage
        .update_conversation(username, &message.sender_id, &ratchet)
        .await
    {
        eprintln!("failed to update conversation: {}", err);
    }

    let is_current = {
        let guard = active_conversation.lock().await;
        guard.receiver.as_deref() == Some(message.sender_id.as_str())
    };
    if is_current {
        let mut guard = active_conversation.lock().await;
        guard.ratchet_state = Some(ratchet);
    }

    let notice = if is_current {
        format!("key exchange completed with {}", message.sender_id)
    } else {
        format!("key exchange completed with {} (stored)", message.sender_id)
    };
    print_incoming(&format_chat_line(timestamp, "system", &notice));
}

async fn handle_encrypted_message(
    message: newspeak::EncryptedMessage,
    active_conversation: &Arc<Mutex<ActiveConversation>>,
    storage: &LocalStorage,
    username: &str,
) {
    let timestamp = timestamp_seconds(message.timestamp.as_ref());
    let sender_id = message.sender_id.clone();
    let aad = ratchet_aad(message.sender_id.as_str(), message.receiver_id.as_str());
    let Some(inner) = message.ratchet_message else {
        eprintln!("missing ratchet message");
        return;
    };
    let ratchet_message = match RatchetMessage::try_from(inner) {
        Ok(msg) => msg,
        Err(err) => {
            eprintln!("invalid ratchet message: {}", err);
            return;
        }
    };
    let is_current = {
        let guard = active_conversation.lock().await;
        guard.receiver.as_deref() == Some(sender_id.as_str())
    };
    if is_current {
        let mut guard = active_conversation.lock().await;
        if guard.ratchet_state.is_none() {
            if let Ok(Some(state)) = storage.get_conversation(username, &sender_id).await {
                guard.ratchet_state = Some(state);
            }
        }
        if let Some(ratchet) = guard.ratchet_state.as_mut() {
            match ratchet.receive_message(ratchet_message, &aad) {
                Ok(plaintext) => {
                    print_incoming(&format_chat_line(timestamp, &sender_id, &plaintext));
                    if let Err(err) = storage
                        .add_message(username, &sender_id, &plaintext, false, timestamp)
                        .await
                    {
                        eprintln!("failed to store message: {}", err);
                    }
                    if let Err(err) = storage
                        .update_conversation(username, &sender_id, ratchet)
                        .await
                    {
                        eprintln!("failed to update conversation: {}", err);
                    }
                }
                Err(err) => {
                    println!("failed to receive mesesage: {}", err.to_string());
                }
            }
        } else {
            eprintln!("received message before key exchange");
        }
        return;
    }

    let mut ratchet = match storage.get_conversation(username, &sender_id).await {
        Ok(Some(state)) => state,
        Ok(None) => {
            eprintln!("received message before key exchange");
            return;
        }
        Err(err) => {
            eprintln!("failed to load conversation: {}", err);
            return;
        }
    };
    match ratchet.receive_message(ratchet_message, &aad) {
        Ok(plaintext) => {
            if let Err(err) = storage
                .add_message(username, &sender_id, &plaintext, false, timestamp)
                .await
            {
                eprintln!("failed to store message: {}", err);
            }
            if let Err(err) = storage
                .update_conversation(username, &sender_id, &ratchet)
                .await
            {
                eprintln!("failed to update conversation: {}", err);
            }
            print_incoming(&format_chat_line(
                timestamp,
                "system",
                &format!("new message from {} (stored)", sender_id),
            ));
        }
        Err(err) => {
            println!("failed to receive mesesage: {}", err.to_string());
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet_aad_allows_valid_metadata() {
        let shared_key: [u8; 32] = rand::random();
        let mut bob = RatchetState::as_receiver(shared_key);
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
        let mut bob = RatchetState::as_receiver(shared_key);
        let bob_pk = x25519::PublicKey::from(&bob.sending_sk);
        let mut alice = RatchetState::as_initiator(shared_key, bob_pk);

        let aad = ratchet_aad("alice", "bob");
        let message = alice.send_message("secret", &aad).unwrap();

        let wrong_aad = ratchet_aad("alice", "carol");
        assert!(bob.receive_message(message, &wrong_aad).is_err());
    }
}

fn parse_args() -> Result<(String, Option<String>)> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Err(anyhow!("usage: newspeak <you> [optional username]"));
    }

    Ok((args[1].clone(), args.get(2).cloned()))
}

fn stdin_lines() -> StdinLines {
    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    reader.lines()
}

/// setup_message_stream sets up the gRPC message stream with the server for the given user.
async fn setup_message_stream(
    user: &User<'_>,
) -> Result<(mpsc::Sender<ClientMessage>, tonic::Streaming<ServerMessage>)> {
    let (tx, rx) = mpsc::channel(32);
    let response = user
        .client
        .clone()
        .message_stream(ReceiverStream::new(rx))
        .await?;
    Ok((tx, response.into_inner()))
}

/// send_join_request sends a join request to the server with the user's signed authentication
/// challenge.
async fn send_join_request(user: &User<'_>, tx: &mpsc::Sender<ClientMessage>) -> Result<()> {
    let auth_signature = user.sign_auth_challenge().await?;
    tx.send(ClientMessage {
        message_type: Some(client_message::MessageType::JoinRequest(JoinRequest {
            username: user.username.to_string(),
            signature: auth_signature,
        })),
    })
    .await?;
    Ok(())
}

/// load_conversation_history loads the conversation history with a given receiver from local
/// storage.
async fn load_conversation_history(
    storage: &LocalStorage,
    username: &str,
    receiver: &str,
) -> Result<Option<RatchetState>> {
    let stored_conversation = storage.get_conversation(username, receiver).await?;
    if stored_conversation.is_some() {
        println!("loaded conversation state for {}", receiver);
        let history = storage
            .get_conversation_messages(username, receiver)
            .await?;
        for message in history {
            let sender = if message.is_sender {
                username
            } else {
                receiver
            };
            println!(
                "{}",
                format_chat_line(message.timestamp, sender, &message.content)
            );
        }
    }
    Ok(stored_conversation)
}

/// prompt_switch_conversation prompts the user to switch to a different conversation.
/// It lists available conversations and updates the active conversation state if a valid
/// choice is made.
async fn prompt_switch_conversation(
    lines: &mut StdinLines,
    username: &str,
    active_conversation: &Arc<Mutex<ActiveConversation>>,
    storage: &LocalStorage,
) -> Result<()> {
    let current = {
        let guard = active_conversation.lock().await;
        guard.receiver.clone()
    };
    let mut conversations = storage.get_user_conversations(username).await?;
    if let Some(current) = current.as_ref() {
        if !conversations.iter().any(|name| name == current) {
            conversations.push(current.clone());
        }
    }
    conversations.sort();

    if conversations.is_empty() {
        print_incoming(&format_chat_line(
            now_unix_seconds(),
            "system",
            "no conversations yet; use /init <username>",
        ));
        return Ok(());
    }

    println!("available conversations:");
    for convo in &conversations {
        if current.as_deref() == Some(convo.as_str()) {
            println!("  {} (current)", convo);
        } else {
            println!("  {}", convo);
        }
    }
    println!("type a username to switch (or press Enter to cancel):");

    let Some(input) = lines.next_line().await? else {
        return Ok(());
    };
    let choice = input.trim();
    if choice.is_empty() || current.as_deref() == Some(choice) {
        print_incoming(&format_chat_line(
            now_unix_seconds(),
            "system",
            "staying on current conversation",
        ));
        return Ok(());
    }
    if !conversations.iter().any(|name| name == choice) {
        print_incoming(&format_chat_line(
            now_unix_seconds(),
            "system",
            "unknown conversation; staying on current",
        ));
        return Ok(());
    }

    let stored_conversation = load_conversation_history(storage, username, choice).await?;
    if stored_conversation.is_none() {
        print_incoming(&format_chat_line(
            now_unix_seconds(),
            "system",
            "missing conversation state; staying on current",
        ));
        return Ok(());
    }

    {
        let mut guard = active_conversation.lock().await;
        guard.receiver = Some(choice.to_string());
        guard.ratchet_state = stored_conversation;
    }

    print_incoming(&format_chat_line(
        now_unix_seconds(),
        "system",
        &format!("switched to {}", choice),
    ));

    Ok(())
}

/// handle_join_response processes the join response from the server, printing any messages
/// and handling offline messages if present.
async fn handle_join_response(
    join: JoinResponse,
    key_info: &Arc<Mutex<KeyExchangeUser>>,
    active_conversation: &Arc<Mutex<ActiveConversation>>,
    storage: &LocalStorage,
    username: &str,
    tx: &mpsc::Sender<ClientMessage>,
) {
    let timestamp = timestamp_seconds(join.timestamp.as_ref());
    print_incoming(&format_chat_line(timestamp, "server", &join.message));
    if join.offline_messages.is_empty() {
        return;
    }

    let mut latest_timestamp: Option<Timestamp> = None;
    for offline in join.offline_messages {
        let Some(message) = offline.message else {
            continue;
        };
        if let Some(timestamp) = offline.timestamp {
            let update = latest_timestamp
                .as_ref()
                .map_or(true, |current| is_newer_timestamp(&timestamp, current));
            if update {
                latest_timestamp = Some(timestamp.clone());
            }
        }
        let Some(server_message) = server_message_from_client_message(message) else {
            continue;
        };
        match server_message.message_type {
            Some(server_message::MessageType::KeyExchange(message)) => {
                handle_key_exchange_message(
                    message,
                    key_info,
                    active_conversation,
                    storage,
                    username,
                )
                .await;
            }
            Some(server_message::MessageType::Encrypted(message)) => {
                handle_encrypted_message(message, active_conversation, storage, username).await;
            }
            _ => {}
        }
    }
    if let Some(latest) = latest_timestamp {
        let ack = ClientMessage {
            message_type: Some(client_message::MessageType::AckOfflineMessages(
                AckOfflineMessages {
                    latest_timestamp: Some(latest),
                },
            )),
        };
        if let Err(err) = tx.send(ack).await {
            eprintln!("failed to ack offline messages: {}", err);
        }
    }
}

/// spawn_inbound_task spawns a Tokio task to handle incoming server messages from the gRPC stream.
/// It processes different message types and updates the local state accordingly.
fn spawn_inbound_task(
    mut inbound: tonic::Streaming<ServerMessage>,
    key_info: Arc<Mutex<KeyExchangeUser>>,
    active_conversation: Arc<Mutex<ActiveConversation>>,
    storage: LocalStorage,
    username: String,
    tx: mpsc::Sender<ClientMessage>,
    mut joined_tx: Option<oneshot::Sender<()>>,
) {
    tokio::spawn(async move {
        while let Some(message) = inbound.message().await.transpose() {
            match message {
                Ok(server_message) => match server_message.message_type {
                    Some(server_message::MessageType::JoinResponse(join)) => {
                        handle_join_response(
                            join,
                            &key_info,
                            &active_conversation,
                            &storage,
                            &username,
                            &tx,
                        )
                        .await;
                        if let Some(tx) = joined_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                    Some(server_message::MessageType::KeyExchange(message)) => {
                        handle_key_exchange_message(
                            message,
                            &key_info,
                            &active_conversation,
                            &storage,
                            &username,
                        )
                        .await;
                    }
                    Some(server_message::MessageType::Encrypted(message)) => {
                        handle_encrypted_message(
                            message,
                            &active_conversation,
                            &storage,
                            &username,
                        )
                        .await;
                    }
                    None => {
                        eprintln!("server sent an empty message");
                    }
                },
                Err(status) => {
                    eprintln!("stream error: {}", status);
                    break;
                }
            }
        }
    });
}

/// initiate_key_exchange_if_needed checks if a key exchange is needed for the current conversation
/// and initiates it if necessary. It updates the local storage and active conversation state
/// accordingly, and sends the key exchange message to the server.
async fn initiate_key_exchange_if_needed(
    user: &mut User<'_>,
    username: &str,
    receiver: &str,
    active_conversation: &Arc<Mutex<ActiveConversation>>,
    storage: &LocalStorage,
    tx: &mpsc::Sender<ClientMessage>,
) -> Result<()> {
    {
        let guard = active_conversation.lock().await;
        if guard.ratchet_state.is_some() {
            return Ok(());
        }
    }

    let (key_message, r_state, peer_identity) = user
        .create_key_exchange_message(receiver.to_string())
        .await?;
    let store_result = storage
        .store_peer_identity(username, receiver, &peer_identity)
        .await?;
    if matches!(store_result, PeerIdentityStoreResult::ExistingMismatch) {
        return Err(anyhow!(
            "identity key mismatch for {}; refusing to start conversation",
            receiver
        ));
    }
    let show_safety = match store_result {
        PeerIdentityStoreResult::Inserted => true,
        PeerIdentityStoreResult::ExistingMatch { verified } => !verified,
        PeerIdentityStoreResult::ExistingMismatch => false,
    };
    if show_safety {
        let local_identity = {
            let key_info = user.key_info.lock().await;
            key_info.identity_pk.to_bytes()
        };
        let safety_number = verification::safety_number_string(&local_identity, &peer_identity);
        print_safety_number(receiver, &safety_number, false);
    }
    storage
        .update_conversation(username, receiver, &r_state)
        .await?;
    {
        let mut guard = active_conversation.lock().await;
        guard.ratchet_state = Some(r_state);
    }

    tx.send(ClientMessage {
        message_type: Some(client_message::MessageType::KeyExchangeMessage(key_message)),
    })
    .await?;

    let timestamp = now_unix_seconds();
    print_incoming(&format_chat_line(
        timestamp,
        "system",
        &format!("key exchange initiated with {}", receiver),
    ));
    Ok(())
}

/// run_input_loop handles the main input loop for reading user input from stdin, processing
/// commands, and sending messages.
async fn run_input_loop(
    lines: &mut StdinLines,
    user: &mut User<'_>,
    username: &str,
    active_conversation: &Arc<Mutex<ActiveConversation>>,
    storage: &LocalStorage,
    tx: &mpsc::Sender<ClientMessage>,
) -> Result<()> {
    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim();
        if trimmed == "exit" {
            break;
        }

        if trimmed.is_empty() {
            continue;
        }

        if trimmed == "/switch" {
            if let Err(err) =
                prompt_switch_conversation(lines, username, active_conversation, storage).await
            {
                print_incoming(&format_chat_line(
                    now_unix_seconds(),
                    "system",
                    &format!("switch failed: {}", err),
                ));
            }
            continue;
        }

        let mut command_parts = trimmed.split_whitespace();
        if command_parts.next() == Some("/init") {
            let Some(receiver) = command_parts.next() else {
                print_incoming(&format_chat_line(
                    now_unix_seconds(),
                    "system",
                    "usage: /init <username>",
                ));
                continue;
            };
            if receiver == username {
                print_incoming(&format_chat_line(
                    now_unix_seconds(),
                    "system",
                    "cannot start a conversation with yourself",
                ));
                continue;
            }

            let stored_conversation =
                match load_conversation_history(storage, username, receiver).await {
                    Ok(state) => state,
                    Err(err) => {
                        print_incoming(&format_chat_line(
                            now_unix_seconds(),
                            "system",
                            &format!("failed to load conversation: {}", err),
                        ));
                        continue;
                    }
                };

            {
                let mut guard = active_conversation.lock().await;
                guard.receiver = Some(receiver.to_string());
                guard.ratchet_state = stored_conversation;
            }

            print_incoming(&format_chat_line(
                now_unix_seconds(),
                "system",
                &format!("active conversation set to {}", receiver),
            ));

            if let Err(err) = initiate_key_exchange_if_needed(
                user,
                username,
                receiver,
                active_conversation,
                storage,
                tx,
            )
            .await
            {
                print_incoming(&format_chat_line(
                    now_unix_seconds(),
                    "system",
                    &format!("init failed: {}", err),
                ));
            }
            continue;
        }

        if trimmed == "/verify" {
            let receiver = {
                let guard = active_conversation.lock().await;
                guard.receiver.clone()
            };
            let Some(receiver) = receiver else {
                print_incoming(&format_chat_line(
                    now_unix_seconds(),
                    "system",
                    "no active conversation; use /init <username> first",
                ));
                continue;
            };
            match storage
                .mark_peer_identity_verified(username, &receiver)
                .await
            {
                Ok(true) => {
                    print_incoming(&format_chat_line(
                        now_unix_seconds(),
                        "system",
                        &format!("marked {} as verified", receiver),
                    ));
                }
                Ok(false) => {
                    print_incoming(&format_chat_line(
                        now_unix_seconds(),
                        "system",
                        "no identity on record for this peer",
                    ));
                }
                Err(err) => {
                    print_incoming(&format_chat_line(
                        now_unix_seconds(),
                        "system",
                        &format!("verification failed: {}", err),
                    ));
                }
            }
            continue;
        }

        let timestamp = now_unix_seconds();
        let mut guard = active_conversation.lock().await;
        let Some(receiver) = guard.receiver.clone() else {
            print_incoming(&format_chat_line(
                timestamp,
                "system",
                "no active conversation; use /init <username> or /switch",
            ));
            continue;
        };
        if guard.ratchet_state.is_none() {
            match storage.get_conversation(username, &receiver).await {
                Ok(Some(state)) => {
                    guard.ratchet_state = Some(state);
                }
                Ok(None) => {}
                Err(err) => {
                    eprintln!("failed to load conversation: {}", err);
                }
            }
        }

        if let Some(state) = guard.ratchet_state.as_mut() {
            let message_timestamp = Timestamp {
                seconds: timestamp,
                nanos: 0,
            };
            let aad = ratchet_aad(username, &receiver);
            let msg = match state.send_message(&line, &aad) {
                Ok(msg) => msg,
                Err(err) => {
                    println!(
                        "failed to construct message, not sending...: {}",
                        err.to_string()
                    );
                    continue;
                }
            };

            let rpc_message = EncryptedMessage {
                sender_id: username.to_string(),
                receiver_id: receiver.clone(),
                ratchet_message: Some(msg.into()),
                timestamp: Some(message_timestamp.clone()),
            };
            if let Err(err) = storage
                .add_message(username, &receiver, &line, true, timestamp)
                .await
            {
                eprintln!("failed to store message: {}", err);
            }
            if let Err(err) = storage
                .update_conversation(username, &receiver, state)
                .await
            {
                eprintln!("failed to update conversation: {}", err);
            }

            tx.send(ClientMessage {
                message_type: Some(client_message::MessageType::EncryptedMessage(rpc_message)),
            })
            .await?;
            print_outgoing(&format_chat_line(timestamp, username, &line));
        } else {
            print_incoming(&format_chat_line(
                timestamp,
                "system",
                "you need to init the key exchange",
            ));
        }
    }

    Ok(())
}

/// run is the main entry point for the client application. It handles user login, conversation
/// selection, key exchange initiation, and the main input loop for sending and receiving messages.
pub async fn run() -> Result<()> {
    // the user can of course set any username they want, but they cannot impersonate others
    // without having access to their signing keys as the server verifies signatures when joining a
    // stream.
    //
    // TODO: currently they could keep spamming the register route to prevent a legitimate user
    // from registering. there should be some blocking in place to prevent abuse.
    let (username, receiver_arg) = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            println!("{}", err);
            std::process::exit(1);
        }
    };

    let client = NewspeakClient::connect("http://[::1]:10000").await?;
    let storage = LocalStorage::new(&username).await?;
    let key_info = storage.load_or_create_user(&username).await?;
    let mut user = User::new(&username, client, key_info);
    let initial_receiver = receiver_arg.filter(|receiver| !receiver.trim().is_empty());

    println!("logged in as: {}", user.username);

    let mut lines = stdin_lines();
    user.register().await?;

    println!("listening for input (press Ctrl+C to quit)...");

    let (tx, inbound) = setup_message_stream(&user).await?;
    send_join_request(&user, &tx).await?;

    clear_terminal();
    let stored_conversation = match initial_receiver.as_deref() {
        Some(receiver) => load_conversation_history(&storage, &username, receiver).await?,
        None => None,
    };

    let active_conversation = Arc::new(Mutex::new(ActiveConversation::new(
        initial_receiver.clone(),
        stored_conversation,
    )));
    if initial_receiver.is_none() {
        print_incoming(&format_chat_line(
            now_unix_seconds(),
            "system",
            "no active conversation; use /init <username>",
        ));
    }
    let (joined_tx, joined_rx) = oneshot::channel();
    spawn_inbound_task(
        inbound,
        Arc::clone(&user.key_info),
        Arc::clone(&active_conversation),
        storage.clone(),
        username.clone(),
        tx.clone(),
        Some(joined_tx),
    );

    let _ = joined_rx.await;

    // if a receiver was provided on startup, try to initialize it immediately
    if let Some(receiver) = initial_receiver.as_deref() {
        if let Err(err) = initiate_key_exchange_if_needed(
            &mut user,
            &username,
            receiver,
            &active_conversation,
            &storage,
            &tx,
        )
        .await
        {
            print_incoming(&format_chat_line(
                now_unix_seconds(),
                "system",
                &format!("init failed: {}", err),
            ));
        }
    }

    run_input_loop(
        &mut lines,
        &mut user,
        &username,
        &active_conversation,
        &storage,
        &tx,
    )
    .await?;
    Ok(())
}
