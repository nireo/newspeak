pub mod pqxdh;
pub mod newspeak {
    tonic::include_proto!("newspeak");
}

use crate::{
    newspeak::{
        ClientMessage, EncryptedMessage, FetchPrekeyBundleRequest, JoinRequest, KeyKind,
        RatchetMessage, RegisterRequest, ServerMessage, client_message,
        newspeak_client::NewspeakClient, server_message,
    },
    pqxdh::{KeyExchangeUser, PrekeyBundle, PublicSignedMlKemPrekey, PublicSignedPrekey},
};
use anyhow::{Result, anyhow};
use ed25519_dalek as ed25519;
use ml_kem::{Encoded, EncodedSizeUser, MlKem1024Params, kem::EncapsulationKey};
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use x25519_dalek as x25519;

struct User<'a> {
    username: &'a str,
    key_info: KeyExchangeUser,
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
    pub fn new(username: &'a str, client: NewspeakClient<Channel>) -> Self {
        User {
            username,
            key_info: pqxdh::KeyExchangeUser::new(),
            client,
        }
    }

    pub async fn register(&mut self) -> Result<()> {
        let req = RegisterRequest {
            username: self.username.into(),
            identity_key: self.key_info.identity_pk.as_bytes().to_vec(),
            signed_prekey: Some((&self.key_info.signed_prekey).into()),
            one_time_prekeys: vec![],
        };

        self.client.register(req).await?;
        Ok(())
    }

    pub async fn init_key_exchange(&mut self, other: String) -> Result<()> {
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
        let init_output = self.key_info.init_key_exchange(&prekey_bundle)?;
        let init_message = init_output.message();

        let initial_message = newspeak::InitialMessage {
            identity_key: init_message.peer_identity_public_key().as_bytes().to_vec(),
            ephemeral_key: init_message
                .ephemeral_x25519_public_key()
                .as_bytes()
                .to_vec(),
            kem_ciphertext: init_message.mlkem_ciphertext().to_vec(),
            one_time_prekey_id: init_message.one_time_prekey_used(),
            kem_id: init_message.kem_used().to_vec(),
        };

        let _key_exchange_message = newspeak::KeyExchangeMessage {
            sender_id: self.username.to_string(),
            receiver_id,
            initial_message: Some(initial_message),
            timestamp: None,
        };

        Ok(())
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
        Some(server_message::MessageType::KeyExchange(message)) => {
            format!(
                "key exchange from {} to {}",
                message.sender_id, message.receiver_id
            )
        }
        Some(server_message::MessageType::Encrypted(message)) => {
            let ratchet = message.ratchet_message.unwrap_or_default();
            let text = String::from_utf8_lossy(&ratchet.ciphertext);
            format!("message from {}: {}", message.sender_id, text)
        }
        None => "server: empty message".to_string(),
    }
}

fn make_dummy_ratchet_message(payload: Vec<u8>, counter: i32) -> RatchetMessage {
    RatchetMessage {
        public_key: Vec::new(),
        previous_chain_length: 0,
        message_number: counter,
        ciphertext: payload,
        nonce: Vec::new(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let client = NewspeakClient::connect("http://[::1]:10000").await?;

    let mut user = User::new(&args[1], client);
    let receiver = args.get(2).cloned().unwrap_or_else(|| args[1].clone());

    println!("logged in as: {}", user.username);

    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();
    user.register().await?;

    println!("listening for input (press Ctrl+C to quit)...");
    print!("> ");

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

    tokio::spawn(async move {
        while let Some(message) = inbound.message().await.transpose() {
            match message {
                Ok(server_message) => {
                    println!();
                    println!("{}", format_server_message(server_message));
                    print!("> ");
                }
                Err(status) => {
                    eprintln!("stream error: {}", status);
                    break;
                }
            }
        }
    });

    let mut counter = 1;
    while let Some(line) = lines.next_line().await? {
        if line == "exit" {
            break;
        }
        let encrypted_message = EncryptedMessage {
            sender_id: user.username.to_string(),
            receiver_id: receiver.clone(),
            ratchet_message: Some(make_dummy_ratchet_message(line.into_bytes(), counter)),
            timestamp: None,
        };
        counter = counter.saturating_add(1);

        tx.send(ClientMessage {
            message_type: Some(client_message::MessageType::EncryptedMessage(
                encrypted_message,
            )),
        })
        .await?;
        print!("> ");
    }

    Ok(())
}
