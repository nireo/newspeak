pub mod local_store;
pub mod pqxdh;
pub mod ratchet;
pub mod newspeak {
    tonic::include_proto!("newspeak");
}

use crate::{
    local_store::LocalStorage,
    newspeak::{
        ClientMessage, EncryptedMessage, FetchPrekeyBundleRequest, InitialMessage, JoinRequest,
        KeyKind, RatchetMessage as ProtoRatchetMessage, RegisterRequest, ServerMessage,
        client_message, newspeak_client::NewspeakClient, server_message,
    },
    pqxdh::{
        KeyExchangeUser, PQXDHInitMessage, PrekeyBundle, PublicSignedMlKemPrekey,
        PublicSignedPrekey,
    },
    ratchet::{RatchetMessage, RatchetState},
};
use anyhow::{Result, anyhow};
use ed25519_dalek as ed25519;
use ml_kem::{Encoded, EncodedSizeUser, MlKem1024Params, kem::EncapsulationKey};
use std::io::Write;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use x25519_dalek as x25519;

struct User<'a> {
    username: &'a str,
    key_info: Arc<Mutex<KeyExchangeUser>>,
    client: NewspeakClient<Channel>,
}

impl From<&pqxdh::SignedPrekey> for newspeak::SignedPrekey {
    fn from(k: &pqxdh::SignedPrekey) -> Self {
        newspeak::SignedPrekey {
            kind: KeyKind::X25519.into(),
            key: k.public_key.as_bytes().to_vec(),
            signature: k.signature.to_vec(),
        }
    }
}

impl From<&pqxdh::SignedMlKemPrekey> for newspeak::SignedPrekey {
    fn from(k: &pqxdh::SignedMlKemPrekey) -> Self {
        newspeak::SignedPrekey {
            kind: KeyKind::MlKem1024.into(),
            key: k.encap_key.as_bytes().as_slice().to_vec(),
            signature: k.signature.to_vec(),
        }
    }
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
        }
    }

    pub async fn register(&mut self) -> Result<()> {
        let key_info = self.key_info.lock().await;
        let req = RegisterRequest {
            username: self.username.into(),
            identity_key: key_info.identity_pk.as_bytes().to_vec(),
            signed_prekey: Some((&key_info.signed_prekey).into()),
            one_time_prekeys: vec![],
            kem_prekey: Some((&key_info.last_resort_kem).into()),
        };

        self.client.register(req).await?;
        Ok(())
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

fn format_server_message(message: ServerMessage) -> String {
    match message.message_type {
        Some(server_message::MessageType::JoinResponse(join)) => {
            format!("server: {}", join.message)
        }
        _ => "server: event".to_string(),
    }
}

fn print_prompt() {
    print!("> ");
    let _ = std::io::stdout().flush();
}

fn print_incoming(message: &str) {
    print!("\r\x1b[2K");
    println!("{}", message);
    print_prompt();
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

const RATCHET_AD: &[u8] = b"ratchet-ad";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let client = NewspeakClient::connect("http://[::1]:10000").await?;

    if args.len() < 3 {
        println!("usage: newspeak <you> <username>");
        std::process::exit(1);
    }

    let storage = LocalStorage::new().await?;
    let key_info = storage.load_or_create_user(&args[1]).await?;
    let mut user = User::new(&args[1], client, key_info);
    let receiver = args.get(2).cloned().unwrap_or_else(|| args[1].clone());

    println!("logged in as: {}", user.username);

    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();
    user.register().await?;

    println!("listening for input (press Ctrl+C to quit)...");
    print_prompt();

    let (tx, rx) = mpsc::channel(32);
    let response = user
        .client
        .clone()
        .message_stream(ReceiverStream::new(rx))
        .await?;
    let mut inbound = response.into_inner();

    tx.send(ClientMessage {
        message_type: Some(client_message::MessageType::JoinRequest(JoinRequest {
            username: user.username.to_string(),
            signature: Vec::new(),
        })),
    })
    .await?;

    let stored_conversation = storage
        .get_conversation(&args[1], &receiver)
        .await?;
    if stored_conversation.is_some() {
        println!("loaded conversation state for {}", receiver);
        let history = storage
            .get_conversation_messages(&args[1], &receiver)
            .await?;
        for message in history {
            if message.is_sender {
                println!("you: {}", message.content);
            } else {
                println!("{}: {}", receiver, message.content);
            }
        }
    }
    let ratchet_state = Arc::new(Mutex::new(stored_conversation));
    let key_info = Arc::clone(&user.key_info);
    let ratchet_state_inbound = Arc::clone(&ratchet_state);
    let storage_inbound = storage.clone();
    let username_inbound = args[1].clone();
    tokio::spawn(async move {
        while let Some(message) = inbound.message().await.transpose() {
            match message {
                Ok(server_message) => match server_message.message_type {
                    Some(server_message::MessageType::JoinResponse(_)) => {
                        let message = format_server_message(server_message);
                        print_incoming(&message);
                    }
                    Some(server_message::MessageType::KeyExchange(message)) => {
                        let Some(init_message) = message.initial_message.as_ref() else {
                            eprintln!("missing initial message in key exchange");
                            continue;
                        };

                        let init = match pqxdh_init_from_proto(init_message) {
                            Ok(init) => init,
                            Err(err) => {
                                eprintln!("failed to parse key exchange: {}", err);
                                continue;
                            }
                        };

                        let key_info = key_info.lock().await;
                        let shared_key = match key_info.receive_key_exchange(&init) {
                            Ok(shared_key) => shared_key,
                            Err(err) => {
                                eprintln!("failed to receive key exchange: {}", err);
                                continue;
                            }
                        };

                        let mut ratchet = RatchetState::new();
                        ratchet.as_receiver(shared_key);
                        ratchet.sending_sk = key_info.signed_prekey.private_key.clone();
                        ratchet.sending_pk = x25519::PublicKey::from(&ratchet.sending_sk);
                        drop(key_info);
                        let mut guard = ratchet_state_inbound.lock().await;
                        *guard = Some(ratchet);
                        if let Some(state) = guard.as_ref() {
                            if let Err(err) = storage_inbound
                                .update_conversation(&username_inbound, &message.sender_id, state)
                                .await
                            {
                                eprintln!("failed to update conversation: {}", err);
                            }
                        }

                        print_incoming(&format!(
                            "key exchange completed with {}",
                            message.sender_id
                        ));
                    }
                    Some(server_message::MessageType::Encrypted(message)) => {
                        let Some(inner) = message.ratchet_message else {
                            eprintln!("missing ratchet message");
                            continue;
                        };
                        let ratchet_message = match ratchet_message_from_proto(inner) {
                            Ok(msg) => msg,
                            Err(err) => {
                                eprintln!("invalid ratchet message: {}", err);
                                continue;
                            }
                        };
                        let mut guard = ratchet_state_inbound.lock().await;
                        if guard.is_none() {
                            if let Ok(Some(state)) = storage_inbound
                                .get_conversation(&username_inbound, &message.sender_id)
                                .await
                            {
                                *guard = Some(state);
                            }
                        }
                        if let Some(ratchet) = guard.as_mut() {
                            match ratchet.receive_message(ratchet_message, RATCHET_AD) {
                                Ok(plaintext) => {
                                    print_incoming(&format!(
                                        "< received [{}]: {}",
                                        ratchet.receiving_counter - 1,
                                        plaintext
                                    ));
                                    if let Err(err) = storage_inbound
                                        .add_message(&username_inbound, &message.sender_id, &plaintext, false)
                                        .await
                                    {
                                        eprintln!("failed to store message: {}", err);
                                    }
                                    if let Err(err) = storage_inbound
                                        .update_conversation(&username_inbound, &message.sender_id, ratchet)
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

    while let Some(line) = lines.next_line().await? {
        if line == "exit" {
            break;
        }

        if line == "" {
            print_prompt();
            continue;
        }

        // TODO: this should automatically be done, however currently there is no way of storing
        // messages and therefore both clients need to connect before writing this message.
        if line == "/init" {
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

            print_prompt();
            continue;
        }

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

            let rpc_message = EncryptedMessage {
                sender_id: args[1].clone(),
                receiver_id: receiver.clone(),
                ratchet_message: Some(ratchet_message_to_proto(msg)),
                timestamp: None,
            };
            if let Err(err) = storage.add_message(&args[1], &receiver, &line, true).await {
                eprintln!("failed to store message: {}", err);
            }
            if let Err(err) = storage.update_conversation(&args[1], &receiver, s).await {
                eprintln!("failed to update conversation: {}", err);
            }

            tx.send(ClientMessage {
                message_type: Some(client_message::MessageType::EncryptedMessage(rpc_message)),
            })
            .await?;
        } else {
            println!("you need to init the key exchange");
        }
        print_prompt();
    }

    Ok(())
}
