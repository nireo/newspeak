pub mod local_store;
pub mod pqxdh;
pub mod ratchet;
pub mod newspeak {
    tonic::include_proto!("newspeak");
}

use crate::{
    local_store::LocalStorage,
    newspeak::{
        AckOfflineMessages, AddSignedPrekeysRequest, ClientMessage, EncryptedMessage,
        FetchPrekeyBundleRequest, InitialMessage, JoinRequest, KeyKind,
        RatchetMessage as ProtoRatchetMessage, RegisterRequest, ServerMessage, client_message,
        newspeak_client::NewspeakClient, server_message,
    },
    pqxdh::{
        KeyExchangeUser, PQXDHInitMessage, PrekeyBundle, PublicSignedMlKemPrekey,
        PublicSignedPrekey,
    },
    ratchet::{RatchetMessage, RatchetState},
};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Local};
use ed25519_dalek::{self as ed25519, Signer};
use ml_kem::{Encoded, EncodedSizeUser, MlKem1024Params, kem::EncapsulationKey};
use prost_types::Timestamp;
use std::io::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use x25519_dalek as x25519;

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

    pub async fn sign_auth_challenge(&self) -> Result<Vec<u8>> {
        let challenge = self
            .auth_challenge
            .ok_or_else(|| anyhow!("missing auth challenge; register first"))?;
        let key_info = self.key_info.lock().await;
        let signature = key_info.identity_sk.sign(&challenge);
        Ok(signature.to_bytes().to_vec())
    }

    pub async fn create_key_exchange_message(
        &mut self,
        other: String,
    ) -> Result<(newspeak::KeyExchangeMessage, RatchetState)> {
        let receiver_id = other.clone();
        let response = self
            .client
            .fetch_prekey_bundle(FetchPrekeyBundleRequest { username: other })
            .await?
            .into_inner();

        let bundle = response
            .bundle
            .ok_or_else(|| anyhow!("missing prekey bundle in response"))?;
        let prekey_bundle = pqxdh_prekey_bundle_from_proto(&bundle)?;
        let key_info = self.key_info.lock().await;
        let init_output = key_info.init_key_exchange(&prekey_bundle)?;
        let init_message = init_output.message;

        let mut ratchet_state = RatchetState::new();
        ratchet_state.as_initiator(
            init_output.secret_key.clone(),
            prekey_bundle.signed_prekey.public_key.clone(),
        );

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
        ))
    }
}

fn pqxdh_prekey_bundle_from_proto(bundle: &newspeak::PrekeyBundle) -> Result<PrekeyBundle> {
    let identity_key = parse_ed25519_public_key(&bundle.identity_key)?;

    let signed_prekey = bundle
        .signed_prekey
        .as_ref()
        .ok_or_else(|| anyhow!("missing signed_prekey in bundle"))?;
    let signed_prekey = parse_x25519_signed_prekey(signed_prekey)?;

    let kem_encap_key = bundle
        .kem_encap_key
        .as_ref()
        .ok_or_else(|| anyhow!("missing kem_encap_key in bundle"))?;
    let kem_encap_key = parse_ml_kem_signed_prekey(kem_encap_key)?;

    let one_time_prekey = bundle
        .one_time_prekey
        .as_ref()
        .map(parse_x25519_signed_prekey)
        .transpose()?;

    let kem_id = parse_kem_id(&bundle.kem_id)?;

    Ok(PrekeyBundle::new(
        signed_prekey,
        kem_encap_key,
        identity_key,
        one_time_prekey,
        bundle.one_time_prekey_id,
        kem_id,
    ))
}

fn parse_ed25519_public_key(bytes: &[u8]) -> Result<ed25519::VerifyingKey> {
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid ed25519 public key length: {}", bytes.len()))?;
    ed25519::VerifyingKey::from_bytes(&key_bytes).map_err(|_| anyhow!("invalid ed25519 public key"))
}

fn parse_ed25519_signature(bytes: &[u8]) -> Result<ed25519::Signature> {
    let signature_bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid ed25519 signature length: {}", bytes.len()))?;
    Ok(ed25519::Signature::from_bytes(&signature_bytes))
}

fn parse_x25519_public_key(bytes: &[u8]) -> Result<x25519::PublicKey> {
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid x25519 public key length: {}", bytes.len()))?;
    Ok(x25519::PublicKey::from(key_bytes))
}

fn parse_kem_encapsulation_key(bytes: &[u8]) -> Result<EncapsulationKey<MlKem1024Params>> {
    let expected = Encoded::<EncapsulationKey<MlKem1024Params>>::default().len();
    if bytes.len() != expected {
        return Err(anyhow!(
            "invalid ML-KEM encapsulation key length: {}",
            bytes.len()
        ));
    }

    let encoded = Encoded::<EncapsulationKey<MlKem1024Params>>::try_from(bytes)
        .map_err(|_| anyhow!("invalid ML-KEM encapsulation key length: {}", bytes.len()))?;
    Ok(EncapsulationKey::from_bytes(&encoded))
}

fn parse_kem_id(bytes: &[u8]) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid kem_id length: {}", bytes.len()))
}

fn parse_x25519_signed_prekey(prekey: &newspeak::SignedPrekey) -> Result<PublicSignedPrekey> {
    let kind =
        KeyKind::try_from(prekey.kind).map_err(|_| anyhow!("unknown key kind {}", prekey.kind))?;
    if kind != KeyKind::X25519 {
        return Err(anyhow!("expected x25519 signed prekey"));
    }

    Ok(PublicSignedPrekey {
        public_key: parse_x25519_public_key(&prekey.key)?,
        signature: parse_ed25519_signature(&prekey.signature)?,
    })
}

fn parse_ml_kem_signed_prekey(prekey: &newspeak::SignedPrekey) -> Result<PublicSignedMlKemPrekey> {
    let kind =
        KeyKind::try_from(prekey.kind).map_err(|_| anyhow!("unknown key kind {}", prekey.kind))?;
    if kind != KeyKind::MlKem1024 {
        return Err(anyhow!("expected ML-KEM-1024 signed prekey"));
    }

    Ok(PublicSignedMlKemPrekey {
        encap_key: parse_kem_encapsulation_key(&prekey.key)?,
        signature: parse_ed25519_signature(&prekey.signature)?,
    })
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

fn ratchet_message_to_proto(message: RatchetMessage) -> ProtoRatchetMessage {
    ProtoRatchetMessage {
        public_key: message.header.pk.as_bytes().to_vec(),
        previous_chain_length: 0,
        message_number: message.header.counter as i32,
        ciphertext: message.ciphertext,
        nonce: message.header.nonce.to_vec(),
    }
}

fn ratchet_message_from_proto(message: ProtoRatchetMessage) -> Result<RatchetMessage> {
    let pk = parse_x25519_public_key(&message.public_key)?;
    if message.message_number < 0 {
        return Err(anyhow!("invalid ratchet message counter"));
    }

    let nonce: [u8; 12] = message
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid ratchet nonce length: {}", message.nonce.len()))?;

    Ok(RatchetMessage {
        header: ratchet::RatchetMessageHeader {
            pk,
            counter: message.message_number as u64,
            nonce,
        },
        ciphertext: message.ciphertext,
    })
}

fn pqxdh_init_from_proto(message: &InitialMessage) -> Result<PQXDHInitMessage> {
    Ok(PQXDHInitMessage {
        peer_identity_public_key: parse_ed25519_public_key(&message.identity_key)?,
        ephemeral_x25519_public_key: parse_x25519_public_key(&message.ephemeral_key)?,
        mlkem_ciphertext: message.kem_ciphertext.clone(),
        kem_used: parse_kem_id(&message.kem_id)?,
        one_time_prekey_used: message.one_time_prekey_id,
    })
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
    ratchet_state: &Arc<Mutex<Option<RatchetState>>>,
    storage: &LocalStorage,
    username: &str,
) {
    let timestamp = timestamp_seconds(message.timestamp.as_ref());
    let Some(init_message) = message.initial_message.as_ref() else {
        eprintln!("missing initial message in key exchange");
        return;
    };

    let init = match pqxdh_init_from_proto(init_message) {
        Ok(init) => init,
        Err(err) => {
            eprintln!("failed to parse key exchange: {}", err);
            return;
        }
    };

    let key_info = key_info.lock().await;
    let shared_key = match key_info.receive_key_exchange(&init) {
        Ok(shared_key) => shared_key,
        Err(err) => {
            eprintln!("failed to receive key exchange: {}", err);
            return;
        }
    };

    let mut ratchet = RatchetState::new();
    ratchet.as_receiver(shared_key);
    ratchet.sending_sk = key_info.signed_prekey.private_key.clone();
    ratchet.sending_pk = x25519::PublicKey::from(&ratchet.sending_sk);
    drop(key_info);

    let mut guard = ratchet_state.lock().await;
    *guard = Some(ratchet);
    if let Some(state) = guard.as_ref() {
        if let Err(err) = storage
            .update_conversation(username, &message.sender_id, state)
            .await
        {
            eprintln!("failed to update conversation: {}", err);
        }
    }

    print_incoming(&format_chat_line(
        timestamp,
        "system",
        &format!("key exchange completed with {}", message.sender_id),
    ));
}

async fn handle_encrypted_message(
    message: newspeak::EncryptedMessage,
    ratchet_state: &Arc<Mutex<Option<RatchetState>>>,
    storage: &LocalStorage,
    username: &str,
) {
    let timestamp = timestamp_seconds(message.timestamp.as_ref());
    let Some(inner) = message.ratchet_message else {
        eprintln!("missing ratchet message");
        return;
    };
    let ratchet_message = match ratchet_message_from_proto(inner) {
        Ok(msg) => msg,
        Err(err) => {
            eprintln!("invalid ratchet message: {}", err);
            return;
        }
    };
    let mut guard = ratchet_state.lock().await;
    if guard.is_none() {
        if let Ok(Some(state)) = storage.get_conversation(username, &message.sender_id).await {
            *guard = Some(state);
        }
    }
    if let Some(ratchet) = guard.as_mut() {
        match ratchet.receive_message(ratchet_message, RATCHET_AD) {
            Ok(plaintext) => {
                print_incoming(&format_chat_line(timestamp, &message.sender_id, &plaintext));
                if let Err(err) = storage
                    .add_message(username, &message.sender_id, &plaintext, false, timestamp)
                    .await
                {
                    eprintln!("failed to store message: {}", err);
                }
                if let Err(err) = storage
                    .update_conversation(username, &message.sender_id, ratchet)
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
}

const RATCHET_AD: &[u8] = b"ratchet-ad";

async fn choose_conversation(username: &str, store: &LocalStorage) -> anyhow::Result<String> {
    let conversations = store.get_user_conversations(username).await?;

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);

    if conversations.is_empty() {
        println!("no conversations found, please enter a username to start a new conversation:");
        let mut input = String::new();

        reader.read_line(&mut input).await?;
        Ok(input.trim().to_string())
    } else {
        println!("existing conversations:");
        for (i, convo) in conversations.iter().enumerate() {
            println!("  {}: {}", i + 1, convo);
        }
        println!("enter the number of the conversation to continue, or enter a new username:");

        let mut input = String::new();
        reader.read_line(&mut input).await?;
        let input = input.trim();

        if let Ok(index) = input.parse::<usize>() {
            if index > 0 && index <= conversations.len() {
                return Ok(conversations[index - 1].clone());
            }
        }

        Ok(input.to_string())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let client = NewspeakClient::connect("http://[::1]:10000").await?;

    if args.len() < 2 {
        println!("usage: newspeak <you> <optional username>");
        std::process::exit(1);
    }

    let storage = LocalStorage::new(&args[1]).await?;
    let key_info = storage.load_or_create_user(&args[1]).await?;
    let mut user = User::new(&args[1], client, key_info);
    let receiver = if args.len() < 3 {
        choose_conversation(&args[1], &storage).await?
    } else {
        args.get(2).cloned().unwrap_or_else(|| args[1].clone())
    };

    println!("logged in as: {}", user.username);

    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();
    user.register().await?;

    println!("listening for input (press Ctrl+C to quit)...");

    let (tx, rx) = mpsc::channel(32);
    let response = user
        .client
        .clone()
        .message_stream(ReceiverStream::new(rx))
        .await?;
    let mut inbound = response.into_inner();

    let auth_signature = user.sign_auth_challenge().await?;
    tx.send(ClientMessage {
        message_type: Some(client_message::MessageType::JoinRequest(JoinRequest {
            username: user.username.to_string(),
            signature: auth_signature,
        })),
    })
    .await?;

    clear_terminal();
    let stored_conversation = storage.get_conversation(&args[1], &receiver).await?;
    let found_conversation = stored_conversation.is_some();
    if found_conversation {
        println!("loaded conversation state for {}", receiver);
        let history = storage
            .get_conversation_messages(&args[1], &receiver)
            .await?;
        for message in history {
            let sender = if message.is_sender {
                args[1].as_str()
            } else {
                receiver.as_str()
            };
            println!(
                "{}",
                format_chat_line(message.timestamp, sender, &message.content)
            );
        }
    }

    let ratchet_state = Arc::new(Mutex::new(stored_conversation));
    let key_info = Arc::clone(&user.key_info);
    let ratchet_state_inbound = Arc::clone(&ratchet_state);
    let storage_inbound = storage.clone();
    let username_inbound = args[1].clone();
    let tx_inbound = tx.clone();

    tokio::spawn(async move {
        while let Some(message) = inbound.message().await.transpose() {
            match message {
                Ok(server_message) => match server_message.message_type {
                    Some(server_message::MessageType::JoinResponse(join)) => {
                        let timestamp = timestamp_seconds(join.timestamp.as_ref());
                        print_incoming(&format_chat_line(timestamp, "server", &join.message));
                        if !join.offline_messages.is_empty() {
                            let mut latest_timestamp: Option<Timestamp> = None;
                            for offline in join.offline_messages {
                                let Some(message) = offline.message else {
                                    continue;
                                };
                                if let Some(timestamp) = offline.timestamp {
                                    let update =
                                        latest_timestamp.as_ref().map_or(true, |current| {
                                            is_newer_timestamp(&timestamp, current)
                                        });
                                    if update {
                                        latest_timestamp = Some(timestamp.clone());
                                    }
                                }
                                let Some(server_message) =
                                    server_message_from_client_message(message)
                                else {
                                    continue;
                                };
                                match server_message.message_type {
                                    Some(server_message::MessageType::KeyExchange(message)) => {
                                        handle_key_exchange_message(
                                            message,
                                            &key_info,
                                            &ratchet_state_inbound,
                                            &storage_inbound,
                                            &username_inbound,
                                        )
                                        .await;
                                    }
                                    Some(server_message::MessageType::Encrypted(message)) => {
                                        handle_encrypted_message(
                                            message,
                                            &ratchet_state_inbound,
                                            &storage_inbound,
                                            &username_inbound,
                                        )
                                        .await;
                                    }
                                    _ => {}
                                }
                            }
                            if let Some(latest) = latest_timestamp {
                                let ack = ClientMessage {
                                    message_type: Some(
                                        client_message::MessageType::AckOfflineMessages(
                                            AckOfflineMessages {
                                                latest_timestamp: Some(latest),
                                            },
                                        ),
                                    ),
                                };
                                if let Err(err) = tx_inbound.send(ack).await {
                                    eprintln!("failed to ack offline messages: {}", err);
                                }
                            }
                        }
                    }
                    Some(server_message::MessageType::KeyExchange(message)) => {
                        handle_key_exchange_message(
                            message,
                            &key_info,
                            &ratchet_state_inbound,
                            &storage_inbound,
                            &username_inbound,
                        )
                        .await;
                    }
                    Some(server_message::MessageType::Encrypted(message)) => {
                        handle_encrypted_message(
                            message,
                            &ratchet_state_inbound,
                            &storage_inbound,
                            &username_inbound,
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

    if !found_conversation {
        let (key_message, r_state) = user.create_key_exchange_message(args[2].clone()).await?;
        let mut guard = ratchet_state.lock().await;
        *guard = Some(r_state);
        if let Some(state) = guard.as_ref() {
            storage
                .update_conversation(&args[1], &receiver, state)
                .await?;
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
    }

    while let Some(line) = lines.next_line().await? {
        if line == "exit" {
            break;
        }

        if line == "" {
            continue;
        }

        let timestamp = now_unix_seconds();
        let mut guard = ratchet_state.lock().await;
        if let Some(s) = guard.as_mut() {
            let msg = s.send_message(&line, RATCHET_AD);
            if let Err(err) = &msg {
                println!(
                    "failed to construct message, not sending...: {}",
                    err.to_string()
                )
            }
            let msg = msg.unwrap();

            let message_timestamp = Timestamp {
                seconds: timestamp,
                nanos: 0,
            };
            let rpc_message = EncryptedMessage {
                sender_id: args[1].clone(),
                receiver_id: receiver.clone(),
                ratchet_message: Some(ratchet_message_to_proto(msg)),
                timestamp: Some(message_timestamp.clone()),
            };
            if let Err(err) = storage
                .add_message(&args[1], &receiver, &line, true, timestamp)
                .await
            {
                eprintln!("failed to store message: {}", err);
            }
            if let Err(err) = storage.update_conversation(&args[1], &receiver, s).await {
                eprintln!("failed to update conversation: {}", err);
            }

            tx.send(ClientMessage {
                message_type: Some(client_message::MessageType::EncryptedMessage(rpc_message)),
            })
            .await?;
            print_outgoing(&format_chat_line(timestamp, &args[1], &line));
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
