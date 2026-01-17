use crate::newspeak::newspeak_server::{Newspeak, NewspeakServer};
use crate::newspeak::{
    self, FetchPrekeyBundleRequest, FetchPrekeyBundleResponse, RegisterRequest, RegisterResponse,
};
use dashmap::DashMap;
use ed25519_dalek::{VerifyingKey, ed25519};
use prost::Message;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::time::{self, Duration, Instant};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Code, GrpcMethod, Request, Response, Status, Streaming};
use tracing::{debug, info};

use crate::newspeak::{
    AddSignedPrekeysRequest, AddSignedPrekeysResponse, ClientMessage, JoinResponse, ServerMessage,
    client_message, server_message,
};
use crate::server_store::{OfflineMessageKind, ServerStore, ServerUser, StoredPrekey, init_db};

/// AuthChallenge represents an authentication challenge issued to a client during registeration
/// the point of the auth challenge is to prove possession of the longterm identity key by signing
/// some arbitrary data and returning the signature to the server.
///
/// Since we already have the identity key it makes sense to use it to sign the challenge. However,
/// this also means that an attacker who manages to compromise the identity key can impersonate the
/// user during registeration. But since the identity key is longterm and should be kept secure
/// this is an acceptable risk.
#[derive(Clone)]
struct AuthChallenge {
    created_at: time::Instant,
    data: [u8; 32],
}

/// AUTH_CHALLENGE_TTL defines how long an auth challenge is valid. since currently the auth
/// chalenges is kept in memory, it makes sense to clean them up after some time.
const AUTH_CHALLENGE_TTL: Duration = Duration::from_secs(300);
const AUTH_CHALLENGE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

// init_tracing initializes tracing subscriber with environment filter
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// log_interceptor logs incoming gRPC requests with method and peer address
fn log_interceptor(req: Request<()>) -> Result<Request<()>, Status> {
    let peer_addr = req.remote_addr();
    if let Some(method) = req.extensions().get::<GrpcMethod<'static>>() {
        info!(
            service = method.service(),
            method = method.method(),
            peer_addr = ?peer_addr,
            "grpc request"
        );
    } else {
        info!(peer_addr = ?peer_addr, "grpc request");
    }
    Ok(req)
}

#[derive(Clone)]
struct NewspeakService {
    users: Arc<DashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>,
    server_store: ServerStore,

    // auth_challenges are returned on registeration and to successfully join a stream the handler
    // the client must return a signature for the challenge signed with their longterm identity
    // key.
    auth_challenges: Arc<AsyncMutex<HashMap<String, AuthChallenge>>>,
}

/// now_timestamp returns the current system time as a prost_types::Timestamp and unix seconds
fn now_timestamp() -> Result<(prost_types::Timestamp, i64), Status> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| Status::internal(format!("system time error: {}", e)))?;
    let timestamp = prost_types::Timestamp {
        seconds: now.as_secs() as i64,
        nanos: 0,
    };
    Ok((timestamp, now.as_secs() as i64))
}

/// timestamp_from_unix_secs converts unix seconds to prost_types::Timestamp
fn timestamp_from_unix_secs(seconds: i64) -> Result<prost_types::Timestamp, Status> {
    if seconds < 0 {
        return Err(Status::invalid_argument("invalid message timestamp"));
    }
    Ok(prost_types::Timestamp { seconds, nanos: 0 })
}

fn identity_pk_from_user(user: &ServerUser) -> Result<VerifyingKey, Status> {
    let identity_key_bytes: [u8; 32] = user.identity_key.as_slice().try_into().map_err(|_| {
        Status::internal("stored identity key has invalid length, database corrupted")
    })?;
    VerifyingKey::from_bytes(&identity_key_bytes)
        .map_err(|_| Status::internal("stored identity key is invalid, database corrupted"))
}

fn verify_signed_prekey(
    identity_pk: &VerifyingKey,
    prekey: &newspeak::SignedPrekey,
    expected_kind: newspeak::KeyKind,
) -> Result<(), Status> {
    let kind = newspeak::KeyKind::try_from(prekey.kind)
        .map_err(|_| Status::invalid_argument("invalid key kind"))?;
    if kind != expected_kind {
        return Err(Status::invalid_argument(
            "unexpected key kind in signed prekey",
        ));
    }
    let signature_bytes: [u8; 64] = prekey
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Status::invalid_argument("invalid signature length in signed prekey"))?;
    identity_pk
        .verify_strict(
            &prekey.key,
            &ed25519_dalek::Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| Status::invalid_argument("signed prekey signature verification failed"))?;
    Ok(())
}

// implement conversion from client message to offline message kind with a try from
impl TryFrom<&ClientMessage> for OfflineMessageKind {
    type Error = Status;

    fn try_from(value: &ClientMessage) -> Result<Self, Self::Error> {
        match value.message_type {
            Some(client_message::MessageType::KeyExchangeMessage(_)) => {
                Ok(OfflineMessageKind::KeyExchange)
            }
            Some(client_message::MessageType::EncryptedMessage(_)) => {
                Ok(OfflineMessageKind::Regular)
            }
            _ => Err(Status::invalid_argument("unsupported offline message type")),
        }
    }
}

impl NewspeakService {
    /// apply_timestamp_to_client_message applies the given timestamp to the client message if it
    /// does not already have one.
    fn apply_timestamp_to_client_message(
        message: &mut ClientMessage,
        timestamp: &prost_types::Timestamp,
    ) {
        match message.message_type.as_mut() {
            Some(client_message::MessageType::KeyExchangeMessage(inner)) => {
                if inner.timestamp.is_none() {
                    inner.timestamp = Some(timestamp.clone());
                }
            }
            Some(client_message::MessageType::EncryptedMessage(inner)) => {
                if inner.timestamp.is_none() {
                    inner.timestamp = Some(timestamp.clone());
                }
            }
            _ => {}
        }
    }

    async fn handle_forwardable_message(
        &self,
        message_type: client_message::MessageType,
        users: &Arc<DashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>,
    ) -> Result<(), Status> {
        let mut client_message = ClientMessage {
            message_type: Some(message_type),
        };
        let (timestamp, created_at) = now_timestamp()?;
        Self::apply_timestamp_to_client_message(&mut client_message, &timestamp);

        let (target, server_message) = match client_message.message_type.as_ref() {
            Some(client_message::MessageType::KeyExchangeMessage(inner)) => (
                inner.receiver_id.clone(),
                ServerMessage {
                    message_type: Some(server_message::MessageType::KeyExchange(inner.clone())),
                },
            ),
            Some(client_message::MessageType::EncryptedMessage(inner)) => (
                inner.receiver_id.clone(),
                ServerMessage {
                    message_type: Some(server_message::MessageType::Encrypted(inner.clone())),
                },
            ),
            _ => {
                return Err(Status::invalid_argument("unsupported offline message type"));
            }
        };

        self.forward_message(target, server_message, client_message, created_at, users)
            .await
    }

    async fn purge_expired_auth_challenges(&self) {
        let challenges = Arc::clone(&self.auth_challenges);
        let mut guard = challenges.lock().await;
        guard.retain(|_, challenge| challenge.created_at.elapsed() <= AUTH_CHALLENGE_TTL);
    }

    fn spawn_auth_challenge_cleanup(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut ticker = time::interval(interval);
            loop {
                ticker.tick().await;
                service.purge_expired_auth_challenges().await;
            }
        })
    }

    async fn create_auth_challenge(&self, username: String) -> AuthChallenge {
        let data: [u8; 32] = rand::random();
        let now = Instant::now();

        let challenge = AuthChallenge {
            created_at: now,
            data,
        };

        let challenges = Arc::clone(&self.auth_challenges);
        let mut guard = challenges.lock().await;
        guard.insert(username, challenge.clone());

        challenge
    }

    async fn verify_auth_challenge(
        &self,
        username: String,
        signature: ed25519::Signature,
    ) -> Result<(), Status> {
        let challenges = Arc::clone(&self.auth_challenges);
        let chall = {
            let mut guard = challenges.lock().await;
            let chall = guard.get(&username).cloned();
            match chall {
                Some(chall) => {
                    if chall.created_at.elapsed() > AUTH_CHALLENGE_TTL {
                        guard.remove(&username);
                        return Err(Status::unauthenticated("auth challenge expired"));
                    }
                    chall
                }
                None => {
                    return Err(Status::not_found(
                        "auth challenge not found for user, register to generate new one",
                    ));
                }
            }
        };

        let user = self.server_store.get_user(username.clone()).await?;
        let identity_pk = identity_pk_from_user(&user)?;

        identity_pk
            .verify_strict(&chall.data, &signature)
            .map_err(|_| Status::invalid_argument("signature provided is invalid"))?;

        let mut guard = challenges.lock().await;
        guard.remove(&username);
        drop(guard);

        self.purge_expired_auth_challenges().await;

        Ok(())
    }

    /// handle_client_message handles incoming client messages and routes them accordingly to the
    /// approriate handler based on the message type.
    async fn handle_client_message(
        &self,
        client_message: ClientMessage,
        tx: &mpsc::Sender<Result<ServerMessage, Status>>,
        users: &Arc<DashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>,
        active_username: &mut Option<String>,
    ) -> Result<(), Status> {
        match client_message.message_type {
            Some(client_message::MessageType::JoinRequest(join_request)) => {
                self.handle_join_request(join_request, tx, users, active_username)
                    .await
            }
            Some(client_message::MessageType::KeyExchangeMessage(message)) => {
                self.handle_forwardable_message(
                    client_message::MessageType::KeyExchangeMessage(message),
                    users,
                )
                .await
            }
            Some(client_message::MessageType::EncryptedMessage(message)) => {
                if let Some(ratchet) = message.ratchet_message.as_ref() {
                    debug!(
                        ciphertext_len = ratchet.ciphertext.len(),
                        "received encrypted message"
                    );
                }
                self.handle_forwardable_message(
                    client_message::MessageType::EncryptedMessage(message),
                    users,
                )
                .await
            }
            Some(client_message::MessageType::AckOfflineMessages(ack)) => {
                let Some(username) = active_username.clone() else {
                    return Err(Status::unauthenticated(
                        "join the stream before acknowledging offline messages",
                    ));
                };
                let Some(latest) = ack.latest_timestamp else {
                    return Err(Status::invalid_argument("missing latest timestamp"));
                };
                if latest.seconds < 0 {
                    return Err(Status::invalid_argument("invalid latest timestamp"));
                }
                self.server_store
                    .delete_offline_message(&username, latest.seconds)
                    .await?;
                Ok(())
            }
            None => Err(Status::invalid_argument("missing message type")),
        }
    }

    /// handle_join_request handles a join request from a client and adds the user to the active
    /// users map if the auth challenge is verified successfully.
    async fn handle_join_request(
        &self,
        join_request: newspeak::JoinRequest,
        tx: &mpsc::Sender<Result<ServerMessage, Status>>,
        users: &Arc<DashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>,
        active_username: &mut Option<String>,
    ) -> Result<(), Status> {
        if join_request.username.is_empty() {
            return Err(Status::invalid_argument("username is required"));
        }

        // if the user is already connected reject the join request
        if users.contains_key(&join_request.username) {
            return Err(Status::already_exists("username already connected"));
        }

        // we need to ensure that the auth challenge is successful, otherwise messages could leak
        // to unauthorized users.
        let signature_bytes: [u8; 64] = join_request
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Status::unauthenticated("invalid auth signature length"))?;

        let signature = ed25519::Signature::from_bytes(&signature_bytes);
        self.verify_auth_challenge(join_request.username.clone(), signature)
            .await?;

        users.insert(join_request.username.clone(), tx.clone());

        // fetch offline messages for the user and send them as part of the join response
        // it makes the most sense to send the messages here as this is an authenticated channel
        // and non authenticated users cannot join the stream. this also simplifies the server
        // implementation as we don't need a separate route for fetching offline messages.
        let stored_messages = self
            .server_store
            .get_offline_messages(&join_request.username)
            .await?;
        let mut offline_messages = Vec::new();

        // convert messages to protobuf
        // TODO: make the server store directly return the prost messages to avoid too many
        // conversions
        for stored in stored_messages {
            let timestamp = timestamp_from_unix_secs(stored.created_at)?;
            let mut message = ClientMessage::decode(stored.message.as_slice())
                .map_err(|_| Status::internal("failed to decode offline message"))?;
            Self::apply_timestamp_to_client_message(&mut message, &timestamp);
            offline_messages.push(newspeak::OfflineMessage {
                timestamp: Some(timestamp),
                message: Some(message),
            });
        }

        *active_username = Some(join_request.username);

        let (join_timestamp, _) = now_timestamp()?;
        let _ = tx
            .send(Ok(ServerMessage {
                message_type: Some(server_message::MessageType::JoinResponse(JoinResponse {
                    message: "joined".to_string(),
                    timestamp: Some(join_timestamp),
                    offline_messages,
                })),
            }))
            .await;

        Ok(())
    }

    /// forward_message forwards the given server message to the target user if they are online,
    async fn forward_message(
        &self,
        target: String,
        server_message: ServerMessage,
        client_message: ClientMessage,
        created_at: i64,
        users: &Arc<DashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>,
    ) -> Result<(), Status> {
        // check if the target user is online
        if let Some(peer_tx) = users.get(&target) {
            let _ = peer_tx.send(Ok(server_message)).await;
            return Ok(());
        }

        // the user is offline therefore we need to store the message as an offline message
        let kind: OfflineMessageKind = (&client_message)
            .try_into()
            .map_err(|_| Status::invalid_argument("unsupported offline message type"))?;

        let encoded = client_message.encode_to_vec();
        let (sender_username, receiver_username) = match client_message.message_type {
            Some(client_message::MessageType::KeyExchangeMessage(ref msg)) => {
                (msg.sender_id.as_str(), msg.receiver_id.as_str())
            }
            Some(client_message::MessageType::EncryptedMessage(ref msg)) => {
                (msg.sender_id.as_str(), msg.receiver_id.as_str())
            }
            _ => {
                return Err(Status::invalid_argument(
                    "unsupported offline message payload",
                ));
            }
        };

        self.server_store
            .insert_message(
                kind,
                &encoded,
                sender_username,
                receiver_username,
                created_at,
            )
            .await?;

        Ok(())
    }

    /// remove_active_user removes the active user from the users map when the stream ends
    /// or the connection is closed.
    async fn remove_active_user(
        &self,
        users: &Arc<DashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>,
        active_username: Option<String>,
    ) {
        if let Some(username) = active_username {
            users.remove(&username);
        }
    }
}

#[tonic::async_trait]
impl Newspeak for NewspeakService {
    type MessageStreamStream = ReceiverStream<Result<ServerMessage, Status>>;

    async fn fetch_prekey_bundle(
        &self,
        request: Request<FetchPrekeyBundleRequest>,
    ) -> Result<Response<FetchPrekeyBundleResponse>, Status> {
        let request = request.into_inner();
        if request.username.is_empty() {
            return Err(Status::invalid_argument("username is required"));
        }

        info!(username = %request.username, "fetches prekey bundle");
        let bundle = self
            .server_store
            .fetch_prekey_bundle(request.username)
            .await?;

        let reply = FetchPrekeyBundleResponse {
            bundle: Some(bundle),
        };
        Ok(Response::new(reply))
    }

    async fn message_stream(
        &self,
        request: Request<Streaming<ClientMessage>>,
    ) -> Result<Response<ReceiverStream<Result<ServerMessage, Status>>>, Status> {
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(32);
        let users = Arc::clone(&self.users);
        let service = self.clone();

        tokio::spawn(async move {
            let mut active_username: Option<String> = None;
            while let Some(message) = inbound.message().await.transpose() {
                match message {
                    Ok(client_message) => {
                        if let Err(status) = service
                            .handle_client_message(
                                client_message,
                                &tx,
                                &users,
                                &mut active_username,
                            )
                            .await
                        {
                            let _ = tx.send(Err(status)).await;
                        }
                    }
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                }
            }

            service.remove_active_user(&users, active_username).await;
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn add_signed_prekeys(
        &self,
        request: Request<AddSignedPrekeysRequest>,
    ) -> Result<Response<AddSignedPrekeysResponse>, Status> {
        let request = request.into_inner();
        if request.username.is_empty() {
            return Err(Status::invalid_argument("username is required"));
        }

        // fetch user identity key to verify prekeys
        let user = self.server_store.get_user(request.username).await?;
        let identity_pk = identity_pk_from_user(&user)?;

        let mut x25519_keys = Vec::new();
        let mut kem_keys = Vec::new();

        for key in request.keys {
            let kind = newspeak::KeyKind::try_from(key.kind)
                .map_err(|_| Status::invalid_argument("invalid key kind"))?;

            match kind {
                newspeak::KeyKind::X25519 => {
                    verify_signed_prekey(&identity_pk, &key, newspeak::KeyKind::X25519)?;
                    x25519_keys.push(StoredPrekey {
                        id: i64::from(key.id),
                        prekey: key,
                    });
                }
                newspeak::KeyKind::MlKem1024 => {
                    verify_signed_prekey(&identity_pk, &key, newspeak::KeyKind::MlKem1024)?;
                    kem_keys.push(key);
                }
            }
        }

        let user_id = user.id.ok_or_else(|| Status::internal("user id missing"))?;
        let key_count = self
            .server_store
            .add_one_time_prekeys(user_id, x25519_keys, kem_keys)
            .await?;

        Ok(Response::new(AddSignedPrekeysResponse { key_count }))
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let request = request.into_inner();
        if request.username.is_empty() {
            return Err(Status::invalid_argument("username is required"));
        }

        let username = request.username;

        // if there is a user ignore the insert, if there is one we should just generate the auth
        // challenge. don't know if this is the best idea to have two uses for this route, but it's
        // easier this way.
        let existing_user = self.server_store.get_user(username.clone()).await;
        if let Err(e) = existing_user {
            // check if something else went wrong
            if e.code() != Code::NotFound {
                return Err(e);
            }

            let signed_prekey = request
                .signed_prekey
                .ok_or_else(|| Status::invalid_argument("signed_prekey is required"))?;
            let kem_prekey = request
                .kem_prekey
                .ok_or_else(|| Status::invalid_argument("kem_prekey is required"))?;

            let identity_key = request.identity_key;
            let identity_key_bytes: [u8; 32] = identity_key
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid identity key length"))?;
            let identity_pk = VerifyingKey::from_bytes(&identity_key_bytes)
                .map_err(|_| Status::invalid_argument("invalid identity key"))?;

            // validate all of the keys just in case
            verify_signed_prekey(&identity_pk, &signed_prekey, newspeak::KeyKind::X25519)?;
            verify_signed_prekey(&identity_pk, &kem_prekey, newspeak::KeyKind::MlKem1024)?;

            let one_time_prekeys = request
                .one_time_prekeys
                .into_iter()
                .map(|prekey| {
                    verify_signed_prekey(&identity_pk, &prekey, newspeak::KeyKind::X25519)?;
                    Ok(StoredPrekey {
                        id: i64::from(prekey.id),
                        prekey,
                    })
                })
                .collect::<Result<Vec<_>, Status>>()?;

            let server_user = ServerUser {
                id: None,
                username: username.clone(),
                identity_key,
                signed_prekey,
                kem_prekey,
                one_time_prekeys,
            };

            self.server_store.insert_user(server_user).await?;
        }

        let challenge = self.create_auth_challenge(username).await;
        let reply = RegisterResponse {
            auth_challenge: challenge.data.to_vec(),
        };
        Ok(Response::new(reply))
    }
}

#[cfg(test)]
#[path = "tests/server.rs"]
mod tests;

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let addr = "[::1]:10000".parse()?;
    let db_options = SqliteConnectOptions::new()
        .filename("server_newspeak.db")
        .create_if_missing(true)
        .foreign_keys(true);
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(db_options)
        .await?;
    init_db(&db).await?;
    let svc = NewspeakService {
        users: Arc::new(DashMap::new()),
        server_store: ServerStore::new(db),
        auth_challenges: Arc::new(AsyncMutex::new(HashMap::new())),
    };
    let _auth_cleanup = svc.spawn_auth_challenge_cleanup(AUTH_CHALLENGE_CLEANUP_INTERVAL);

    info!(address = %addr, "NewspeakServer listening");

    Server::builder()
        .add_service(NewspeakServer::with_interceptor(svc, log_interceptor))
        .serve(addr)
        .await?;

    Ok(())
}
