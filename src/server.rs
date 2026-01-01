pub mod newspeak {
    tonic::include_proto!("newspeak");
}

use blake3;
use ed25519_dalek::{VerifyingKey, ed25519};
use newspeak::newspeak_server::{Newspeak, NewspeakServer};
use newspeak::{
    FetchPrekeyBundleRequest, FetchPrekeyBundleResponse, PrekeyBundle, RegisterRequest,
    RegisterResponse, SignedPrekey,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::time::{self, Duration, Instant};
use rusqlite::{self, Connection, Error as RusqliteError, OptionalExtension, params};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use dashmap::DashMap;

use crate::newspeak::{
    AddSignedPrekeysRequest, AddSignedPrekeysResponse, ClientMessage, JoinResponse, ServerMessage,
    client_message, server_message,
};

#[derive(Clone)]
struct AuthChallenge {
    created_at: time::Instant,
    data: [u8; 32],
}

const AUTH_CHALLENGE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct NewspeakService {
    users: Arc<DashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>,
    server_store: ServerStore,

    // auth_challenges are returned on registeration and to successfully join a stream the handler
    // the client must return a signature for the challenge signed with their longterm identity
    // key.
    auth_challenges: Arc<AsyncMutex<HashMap<String, AuthChallenge>>>,
}

impl NewspeakService {
    async fn purge_expired_auth_challenges(&self) {
        let challenges = Arc::clone(&self.auth_challenges);
        let mut guard = challenges.lock().await;
        guard.retain(|_, challenge| challenge.created_at.elapsed() <= AUTH_CHALLENGE_TTL);
    }

    async fn create_auth_challenge(&self, username: String) -> AuthChallenge {
        self.purge_expired_auth_challenges().await;
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
        let identity_key_bytes: [u8; 32] =
            user.identity_key.as_slice().try_into().map_err(|_| {
                Status::internal("stored identity key has invalid length, database corrupted")
            })?;

        // we need to verify that the identity_key matches
        let identity_pk = VerifyingKey::from_bytes(&identity_key_bytes)
            .map_err(|_| Status::internal("stored identity key is invalid, database corrupted"))?;

        identity_pk
            .verify_strict(&chall.data, &signature)
            .map_err(|_| Status::invalid_argument("signature provided is invalid"))?;

        let mut guard = challenges.lock().await;
        guard.remove(&username);
        drop(guard);

        self.purge_expired_auth_challenges().await;

        Ok(())
    }

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
                let target = message.receiver_id.clone();
                let server_message = ServerMessage {
                    message_type: Some(server_message::MessageType::KeyExchange(message)),
                };
                self.forward_message(target, server_message, tx, users)
                    .await;
                Ok(())
            }
            Some(client_message::MessageType::EncryptedMessage(message)) => {
                let target = message.receiver_id.clone();
                println!(
                    "message: {}",
                    hex::encode(&message.ratchet_message.as_ref().unwrap().ciphertext)
                );
                let server_message = ServerMessage {
                    message_type: Some(server_message::MessageType::Encrypted(message)),
                };
                self.forward_message(target, server_message, tx, users)
                    .await;
                Ok(())
            }
            None => Err(Status::invalid_argument("missing message type")),
        }
    }

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

        let signature_bytes: [u8; 64] = join_request
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Status::unauthenticated("invalid auth signature length"))?;
        let signature = ed25519::Signature::from_bytes(&signature_bytes);
        self.verify_auth_challenge(join_request.username.clone(), signature)
            .await?;

        if users.contains_key(&join_request.username) {
            return Err(Status::already_exists("username already connected"));
        }
        users.insert(join_request.username.clone(), tx.clone());
        *active_username = Some(join_request.username);

        let _ = tx
            .send(Ok(ServerMessage {
                message_type: Some(server_message::MessageType::JoinResponse(JoinResponse {
                    message: "joined".to_string(),
                    timestamp: None,
                })),
            }))
            .await;

        Ok(())
    }

    async fn forward_message(
        &self,
        target: String,
        server_message: ServerMessage,
        tx: &mpsc::Sender<Result<ServerMessage, Status>>,
        users: &Arc<DashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>,
    ) {
        if let Some(peer_tx) = users.get(&target) {
            let _ = peer_tx.send(Ok(server_message)).await;
        } else {
            let _ = tx.send(Ok(server_message)).await;
        }
    }

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

struct StoredPrekey {
    id: i64,
    prekey: SignedPrekey,
}

struct ServerUser {
    id: Option<i64>,
    username: String,
    identity_key: Vec<u8>,
    signed_prekey: SignedPrekey,
    kem_prekey: SignedPrekey,
    one_time_prekeys: Vec<StoredPrekey>,
}

#[derive(Clone)]
struct ServerStore {
    db: Arc<StdMutex<Connection>>,
}

impl ServerStore {
    fn new(db: Arc<StdMutex<Connection>>) -> Self {
        Self { db }
    }

    async fn insert_user(&self, user: ServerUser) -> Result<(), Status> {
        let mut conn = self
            .db
            .lock()
            .map_err(|_| Status::internal("database lock poisoned"))?;
        let tx = conn.transaction().map_err(map_db_error)?;

        tx.execute(
            "INSERT INTO users (
                username,
                identity_key,
                signed_prekey_kind,
                signed_prekey_key,
                signed_prekey_signature,
                kem_prekey_kind,
                kem_prekey_key,
                kem_prekey_signature
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                user.username,
                user.identity_key,
                user.signed_prekey.kind,
                user.signed_prekey.key,
                user.signed_prekey.signature,
                user.kem_prekey.kind,
                user.kem_prekey.key,
                user.kem_prekey.signature
            ],
        )
        .map_err(map_db_error)?;

        let user_id = tx.last_insert_rowid();

        for prekey in user.one_time_prekeys {
            insert_one_time_key(&tx, "one_time_prekeys", user_id, prekey.id, &prekey.prekey)
                .map_err(map_db_error)?;
        }
        tx.commit().map_err(map_db_error)?;
        Ok(())
    }

    async fn get_user(&self, username: String) -> Result<ServerUser, Status> {
        let mut conn = self
            .db
            .lock()
            .map_err(|_| Status::internal("database lock poisoned"))?;
        let tx = conn.transaction().map_err(map_db_error)?;

        let user_row: Option<ServerUser> = tx
            .query_row(
                "SELECT id,
                        identity_key,
                        signed_prekey_kind,
                        signed_prekey_key,
                        signed_prekey_signature,
                        kem_prekey_kind,
                        kem_prekey_key,
                        kem_prekey_signature
                FROM users
                WHERE username = ?1",
                params![username.as_str()],
                |row| {
                    let user_id: i64 = row.get(0)?;
                    let identity_key: Vec<u8> = row.get(1)?;
                    let signed_prekey_kind: i32 = row.get(2)?;
                    let signed_prekey_key: Vec<u8> = row.get(3)?;
                    let signed_prekey_signature: Vec<u8> = row.get(4)?;
                    let kem_prekey_kind: i32 = row.get(5)?;
                    let kem_prekey_key: Vec<u8> = row.get(6)?;
                    let kem_prekey_signature: Vec<u8> = row.get(7)?;
                    Ok(ServerUser {
                        id: Some(user_id),
                        username: username.to_string(),
                        identity_key,
                        signed_prekey: SignedPrekey {
                            kind: signed_prekey_kind,
                            key: signed_prekey_key,
                            signature: signed_prekey_signature,
                            id: 0,
                        },
                        kem_prekey: SignedPrekey {
                            kind: kem_prekey_kind,
                            key: kem_prekey_key,
                            signature: kem_prekey_signature,
                            id: 0,
                        },
                        one_time_prekeys: Vec::new(), // to be filled later
                    })
                },
            )
            .optional()
            .map_err(map_db_error)?;

        tx.commit().map_err(map_db_error)?;

        let user = user_row.ok_or_else(|| Status::not_found("username not registered"))?;
        Ok(user)
    }

    async fn fetch_prekey_bundle(&self, username: String) -> Result<PrekeyBundle, Status> {
        let mut conn = self
            .db
            .lock()
            .map_err(|_| Status::internal("database lock poisoned"))?;
        let tx = conn.transaction().map_err(map_db_error)?;

        let user_row: Option<(i64, Vec<u8>, SignedPrekey, SignedPrekey)> = tx
            .query_row(
                "SELECT id,
                        identity_key,
                        signed_prekey_kind,
                        signed_prekey_key,
                        signed_prekey_signature,
                        kem_prekey_kind,
                        kem_prekey_key,
                        kem_prekey_signature
                FROM users
                WHERE username = ?1",
                params![username.as_str()],
                |row| {
                    let user_id: i64 = row.get(0)?;
                    let identity_key: Vec<u8> = row.get(1)?;
                    let signed_prekey_kind: i32 = row.get(2)?;
                    let signed_prekey_key: Vec<u8> = row.get(3)?;
                    let signed_prekey_signature: Vec<u8> = row.get(4)?;
                    let kem_prekey_kind: i32 = row.get(5)?;
                    let kem_prekey_key: Vec<u8> = row.get(6)?;
                    let kem_prekey_signature: Vec<u8> = row.get(7)?;
                    Ok((
                        user_id,
                        identity_key,
                        SignedPrekey {
                            kind: signed_prekey_kind,
                            key: signed_prekey_key,
                            signature: signed_prekey_signature,
                            id: 0,
                        },
                        SignedPrekey {
                            kind: kem_prekey_kind,
                            key: kem_prekey_key,
                            signature: kem_prekey_signature,
                            id: 0,
                        },
                    ))
                },
            )
            .optional()
            .map_err(map_db_error)?;

        let Some((user_id, identity_key, signed_prekey, kem_prekey)) = user_row else {
            return Err(Status::not_found("username not registered"));
        };

        let kem_encap_key =
            take_one_time_key(&tx, "one_time_kem_keys", user_id).map_err(map_db_error)?;
        let (kem_encap_key, kem_id) = match kem_encap_key {
            Some(prekey) => {
                let kem_id = kem_id_from_key(&prekey.prekey.key);
                (prekey.prekey, kem_id)
            }
            None => {
                let kem_id = kem_id_from_key(&kem_prekey.key);
                (kem_prekey, kem_id)
            }
        };
        let one_time_prekey =
            take_one_time_key(&tx, "one_time_prekeys", user_id).map_err(map_db_error)?;
        let (one_time_prekey, one_time_prekey_id) = match one_time_prekey {
            Some(prekey) => (Some(prekey.prekey), Some(prekey.id as u32)),
            None => (None, None),
        };

        tx.commit().map_err(map_db_error)?;

        Ok(PrekeyBundle {
            identity_key,
            signed_prekey: Some(signed_prekey),
            kem_encap_key: Some(kem_encap_key),
            one_time_prekey,
            kem_id,
            one_time_prekey_id,
        })
    }

    async fn add_one_time_prekeys(
        &self,
        user_id: i64,
        prekeys: Vec<StoredPrekey>,
        kem_prekeys: Vec<SignedPrekey>,
    ) -> Result<i32, Status> {
        let mut conn = self
            .db
            .lock()
            .map_err(|_| Status::internal("database lock poisoned"))?;
        let tx = conn.transaction().map_err(map_db_error)?;
        let mut count = 0;
        count += insert_one_time_keys(&tx, "one_time_prekeys", user_id, prekeys)
            .map_err(map_db_error)?;
        let kem_prekeys = kem_prekeys
            .into_iter()
            .map(|prekey| StoredPrekey {
                id: kem_db_id_from_key(&prekey.key),
                prekey,
            })
            .collect();
        count += insert_one_time_keys(&tx, "one_time_kem_keys", user_id, kem_prekeys)
            .map_err(map_db_error)?;
        tx.commit().map_err(map_db_error)?;
        Ok(count)
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

        println!("fetches prekey bundle for: {}", request.username);
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

        let identity_key_bytes: [u8; 32] =
            user.identity_key.as_slice().try_into().map_err(|_| {
                Status::internal("stored identity key has invalid length, database corrupted")
            })?;

        // we need to verify that the identity_key matches
        let identity_pk = VerifyingKey::from_bytes(&identity_key_bytes)
            .map_err(|_| Status::internal("stored identity key is invalid, database corrupted"))?;

        let mut x25519_keys = Vec::new();
        let mut kem_keys = Vec::new();

        for key in request.keys {
            let kind = newspeak::KeyKind::try_from(key.kind)
                .map_err(|_| Status::invalid_argument("invalid key kind"))?;
            let signature_bytes: [u8; 64] = key.signature.as_slice().try_into().map_err(|_| {
                Status::invalid_argument("invalid signature length in signed prekey")
            })?;

            identity_pk
                .verify_strict(
                    &key.key,
                    &ed25519_dalek::Signature::from_bytes(&signature_bytes),
                )
                .map_err(|_| {
                    Status::invalid_argument("signed prekey signature verification failed")
                })?;

            match kind {
                newspeak::KeyKind::X25519 => x25519_keys.push(StoredPrekey {
                    id: i64::from(key.id),
                    prekey: key,
                }),
                newspeak::KeyKind::MlKem1024 => kem_keys.push(key),
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
        let signed_prekey = request
            .signed_prekey
            .ok_or_else(|| Status::invalid_argument("signed_prekey is required"))?;
        let kem_prekey = request
            .kem_prekey
            .ok_or_else(|| Status::invalid_argument("kem_prekey is required"))?;

        let username = request.username;
        let challenge_username = username.clone();
        let identity_key = request.identity_key;
        let one_time_prekeys = request
            .one_time_prekeys
            .into_iter()
            .map(|prekey| StoredPrekey {
                id: i64::from(prekey.id),
                prekey,
            })
            .collect();

        let server_user = ServerUser {
            id: None,
            username,
            identity_key,
            signed_prekey,
            kem_prekey,
            one_time_prekeys,
        };
        self.server_store.insert_user(server_user).await?;

        let challenge = self.create_auth_challenge(challenge_username).await;
        let reply = RegisterResponse {
            auth_challenge: challenge.data.to_vec(),
        };
        Ok(Response::new(reply))
    }
}

fn insert_one_time_key(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    user_id: i64,
    id: i64,
    prekey: &SignedPrekey,
) -> Result<(), RusqliteError> {
    let sql = format!(
        "INSERT INTO {} (
            id,
            user_id,
            kind,
            key,
            signature
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        table
    );

    tx.execute(
        &sql,
        params![id, user_id, prekey.kind, prekey.key, prekey.signature],
    )?;
    Ok(())
}

fn insert_one_time_keys(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    user_id: i64,
    prekeys: Vec<StoredPrekey>,
) -> Result<i32, RusqliteError> {
    let mut count = 0;
    for prekey in prekeys {
        insert_one_time_key(tx, table, user_id, prekey.id, &prekey.prekey)?;
        count += 1;
    }
    Ok(count)
}

fn take_one_time_key(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    user_id: i64,
) -> Result<Option<StoredPrekey>, RusqliteError> {
    let sql = format!(
        "SELECT id, kind, key, signature
        FROM {}
        WHERE user_id = ?1
        ORDER BY id
        LIMIT 1",
        table
    );

    let row: Option<(i64, SignedPrekey)> = tx
        .query_row(&sql, params![user_id], |row| {
            let id: i64 = row.get(0)?;
            let kind: i32 = row.get(1)?;
            let key: Vec<u8> = row.get(2)?;
            let signature: Vec<u8> = row.get(3)?;
            let prekey_id = u32::try_from(id).unwrap_or(0);
            Ok((
                id,
                SignedPrekey {
                    kind,
                    key,
                    signature,
                    id: prekey_id,
                },
            ))
        })
        .optional()?;

    if let Some((id, prekey)) = row {
        let delete_sql = format!("DELETE FROM {} WHERE id = ?1 AND user_id = ?2", table);
        tx.execute(&delete_sql, params![id, user_id])?;
        Ok(Some(StoredPrekey { id, prekey }))
    } else {
        Ok(None)
    }
}

fn kem_id_from_key(key: &[u8]) -> Vec<u8> {
    blake3::hash(key).as_bytes()[..16].to_vec()
}

fn kem_db_id_from_key(key: &[u8]) -> i64 {
    let hash = blake3::hash(key);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash.as_bytes()[..8]);
    i64::from_le_bytes(bytes)
}

fn map_db_error(err: RusqliteError) -> Status {
    match err {
        RusqliteError::SqliteFailure(code, _) => match code.code {
            rusqlite::ErrorCode::ConstraintViolation => {
                Status::already_exists("username already registered")
            }
            _ => Status::internal(format!("database error: {}", code)),
        },
        _ => Status::internal(format!("database error: {}", err)),
    }
}

fn init_db(conn: &Connection) -> Result<(), RusqliteError> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            identity_key BLOB NOT NULL,
            signed_prekey_kind INTEGER NOT NULL,
            signed_prekey_key BLOB NOT NULL,
            signed_prekey_signature BLOB NOT NULL,
            kem_prekey_kind INTEGER NOT NULL,
            kem_prekey_key BLOB NOT NULL,
            kem_prekey_signature BLOB NOT NULL,
            signed_prekey_created_at INTEGER
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

        CREATE TABLE IF NOT EXISTS one_time_prekeys (
            id INTEGER,
            user_id INTEGER,
            kind INTEGER NOT NULL,
            key BLOB NOT NULL,
            signature BLOB NOT NULL,
            created_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (id, user_id)
        );

        CREATE TABLE IF NOT EXISTS one_time_kem_keys (
            id INTEGER,
            user_id INTEGER,
            kind INTEGER NOT NULL,
            key BLOB NOT NULL,
            signature BLOB NOT NULL,
            created_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (id, user_id)
        );",
    )?;
    Ok(())
}

#[cfg(test)]
impl ServerStore {
    async fn count_users_and_prekeys(&self) -> Result<(i64, i64), Status> {
        let conn = self
            .db
            .lock()
            .map_err(|_| Status::internal("database lock poisoned"))?;
        let user_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .map_err(map_db_error)?;
        let prekey_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM one_time_prekeys", [], |row| row.get(0))
            .map_err(map_db_error)?;
        let counts = (user_count, prekey_count);
        Ok(counts)
    }

    async fn count_one_time_keys(&self) -> Result<(i64, i64), Status> {
        let conn = self
            .db
            .lock()
            .map_err(|_| Status::internal("database lock poisoned"))?;
        let prekey_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM one_time_prekeys", [], |row| row.get(0))
            .map_err(map_db_error)?;
        let kem_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM one_time_kem_keys", [], |row| row.get(0))
            .map_err(map_db_error)?;
        let counts = (prekey_count, kem_count);
        Ok(counts)
    }
}

#[cfg(test)]
#[path = "tests/server.rs"]
mod tests;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:10000".parse()?;
    let db = Connection::open("server_newspeak.db")?;
    init_db(&db)?;
    let db = Arc::new(StdMutex::new(db));
    let svc = NewspeakService {
        users: Arc::new(DashMap::new()),
        server_store: ServerStore::new(db),
        auth_challenges: Arc::new(AsyncMutex::new(HashMap::new())),
    };

    println!("NewspeakServer listening on {}", addr);

    Server::builder()
        .add_service(NewspeakServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
