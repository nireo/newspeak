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
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::{self, Duration, Instant};
use tokio_rusqlite::Connection;
use tokio_rusqlite::Error as TokioRusqliteError;
use tokio_rusqlite::rusqlite::{self, Error as RusqliteError, OptionalExtension, params};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

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
    users: Arc<Mutex<HashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>>,
    server_store: ServerStore,

    // auth_challenges are returned on registeration and to successfully join a stream the handler
    // the client must return a signature for the challenge signed with their longterm identity
    // key.
    auth_challenges: Arc<Mutex<HashMap<String, AuthChallenge>>>,
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
    db: Arc<Connection>,
}

impl ServerStore {
    fn new(db: Arc<Connection>) -> Self {
        Self { db }
    }

    async fn insert_user(&self, user: ServerUser) -> Result<(), Status> {
        let db = Arc::clone(&self.db);
        db.call(move |conn| {
            let tx = conn.transaction()?;

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
            )?;

            let user_id = tx.last_insert_rowid();

            for prekey in user.one_time_prekeys {
                insert_one_time_key(&tx, "one_time_prekeys", user_id, prekey.id, &prekey.prekey)?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(map_db_error)?;
        Ok(())
    }

    async fn get_user(&self, username: String) -> Result<ServerUser, Status> {
        let db = Arc::clone(&self.db);
        let user = db
            .call(move |conn| {
                let tx = conn.transaction()?;

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
                        params![username],
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
                    .optional()?;

                if user_row.is_none() {
                    return Ok(None);
                }

                tx.commit()?;

                // unwrap is safe here because of the earlier check
                Ok(Some(user_row.unwrap()))
            })
            .await
            .map_err(map_db_error)?;
        let user = user.ok_or_else(|| Status::not_found("username not registered"))?;
        Ok(user)
    }

    async fn fetch_prekey_bundle(&self, username: String) -> Result<PrekeyBundle, Status> {
        let db = Arc::clone(&self.db);
        let bundle = db
            .call(move |conn| {
                let tx = conn.transaction()?;

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
                        params![username],
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
                    .optional()?;

                let Some((user_id, identity_key, signed_prekey, kem_prekey)) = user_row else {
                    return Ok(None);
                };

                let kem_encap_key = take_one_time_key(&tx, "one_time_kem_keys", user_id)?;
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
                let one_time_prekey = take_one_time_key(&tx, "one_time_prekeys", user_id)?;
                let (one_time_prekey, one_time_prekey_id) = match one_time_prekey {
                    Some(prekey) => (Some(prekey.prekey), Some(prekey.id as u32)),
                    None => (None, None),
                };

                tx.commit()?;

                Ok(Some(PrekeyBundle {
                    identity_key,
                    signed_prekey: Some(signed_prekey),
                    kem_encap_key: Some(kem_encap_key),
                    one_time_prekey,
                    kem_id,
                    one_time_prekey_id,
                }))
            })
            .await
            .map_err(map_db_error)?;

        bundle.ok_or_else(|| Status::not_found("username not registered"))
    }

    async fn add_one_time_prekeys(
        &self,
        user_id: i64,
        prekeys: Vec<StoredPrekey>,
        kem_prekeys: Vec<SignedPrekey>,
    ) -> Result<i32, Status> {
        let db = Arc::clone(&self.db);
        let inserted = db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let mut count = 0;
                count += insert_one_time_keys(&tx, "one_time_prekeys", user_id, prekeys)?;
                let kem_prekeys = kem_prekeys
                    .into_iter()
                    .map(|prekey| StoredPrekey {
                        id: kem_db_id_from_key(&prekey.key),
                        prekey,
                    })
                    .collect();
                count += insert_one_time_keys(&tx, "one_time_kem_keys", user_id, kem_prekeys)?;
                tx.commit()?;
                Ok::<i32, RusqliteError>(count)
            })
            .await
            .map_err(map_db_error)?;
        Ok(inserted)
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
                    Ok(client_message) => match client_message.message_type {
                        Some(client_message::MessageType::JoinRequest(join_request)) => {
                            if join_request.username.is_empty() {
                                let _ = tx
                                    .send(Err(Status::invalid_argument("username is required")))
                                    .await;
                                continue;
                            }

                            let signature_bytes: [u8; 64] =
                                match join_request.signature.as_slice().try_into() {
                                    Ok(bytes) => bytes,
                                    Err(_) => {
                                        let _ = tx
                                            .send(Err(Status::unauthenticated(
                                                "invalid auth signature length",
                                            )))
                                            .await;
                                        continue;
                                    }
                                };
                            let signature = ed25519::Signature::from_bytes(&signature_bytes);
                            if let Err(err) = service
                                .verify_auth_challenge(join_request.username.clone(), signature)
                                .await
                            {
                                let _ = tx.send(Err(err)).await;
                                continue;
                            }

                            let mut guard = users.lock().await;
                            if guard.contains_key(&join_request.username) {
                                let _ = tx
                                    .send(Err(Status::already_exists("username already connected")))
                                    .await;
                                continue;
                            }
                            guard.insert(join_request.username.clone(), tx.clone());
                            active_username = Some(join_request.username);

                            let _ = tx
                                .send(Ok(ServerMessage {
                                    message_type: Some(server_message::MessageType::JoinResponse(
                                        JoinResponse {
                                            message: "joined".to_string(),
                                            timestamp: None,
                                        },
                                    )),
                                }))
                                .await;
                        }
                        Some(client_message::MessageType::KeyExchangeMessage(message)) => {
                            let target = message.receiver_id.clone();
                            let server_message = ServerMessage {
                                message_type: Some(server_message::MessageType::KeyExchange(
                                    message,
                                )),
                            };
                            let guard = users.lock().await;
                            if let Some(peer_tx) = guard.get(&target) {
                                let _ = peer_tx.send(Ok(server_message)).await;
                            } else {
                                let _ = tx.send(Ok(server_message)).await;
                            }
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
                            let guard = users.lock().await;
                            if let Some(peer_tx) = guard.get(&target) {
                                let _ = peer_tx.send(Ok(server_message)).await;
                            } else {
                                let _ = tx.send(Ok(server_message)).await;
                            }
                        }
                        None => {
                            let _ = tx
                                .send(Err(Status::invalid_argument("missing message type")))
                                .await;
                        }
                    },
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                }
            }

            if let Some(username) = active_username {
                let mut guard = users.lock().await;
                guard.remove(&username);
            }
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

fn map_db_error(err: TokioRusqliteError<RusqliteError>) -> Status {
    match err {
        TokioRusqliteError::Error(RusqliteError::SqliteFailure(code, _)) => match code.code {
            rusqlite::ErrorCode::ConstraintViolation => {
                Status::already_exists("username already registered")
            }
            _ => Status::internal(format!("database error: {}", code)),
        },
        TokioRusqliteError::Close((_, err)) => Status::internal(format!("database error: {}", err)),
        _ => Status::internal(format!("database error: {}", err)),
    }
}

async fn init_db(conn: &Connection) -> Result<(), TokioRusqliteError<RusqliteError>> {
    conn.call(|conn| {
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
        Ok::<(), RusqliteError>(())
    })
    .await
}

#[cfg(test)]
impl ServerStore {
    async fn count_users_and_prekeys(&self) -> Result<(i64, i64), Status> {
        let db = Arc::clone(&self.db);
        let counts = db
            .call(|conn| {
                let user_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
                let prekey_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM one_time_prekeys", [], |row| {
                        row.get(0)
                    })?;
                Ok::<(i64, i64), RusqliteError>((user_count, prekey_count))
            })
            .await
            .map_err(map_db_error)?;
        Ok(counts)
    }

    async fn count_one_time_keys(&self) -> Result<(i64, i64), Status> {
        let db = Arc::clone(&self.db);
        let counts = db
            .call(|conn| {
                let prekey_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM one_time_prekeys", [], |row| {
                        row.get(0)
                    })?;
                let kem_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM one_time_kem_keys", [], |row| {
                        row.get(0)
                    })?;
                Ok::<(i64, i64), RusqliteError>((prekey_count, kem_count))
            })
            .await
            .map_err(map_db_error)?;
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use newspeak::KeyKind;
    use tonic::Code;

    fn sample_prekey(kind: KeyKind, key: &[u8], signature: &[u8]) -> SignedPrekey {
        SignedPrekey {
            kind: kind as i32,
            key: key.to_vec(),
            signature: signature.to_vec(),
            id: 0,
        }
    }

    fn sample_prekey_with_id(
        kind: KeyKind,
        key: &[u8],
        signature: &[u8],
        id: u32,
    ) -> SignedPrekey {
        SignedPrekey {
            kind: kind as i32,
            key: key.to_vec(),
            signature: signature.to_vec(),
            id,
        }
    }

    async fn test_service() -> NewspeakService {
        let db = Connection::open(":memory:").await.unwrap();
        init_db(&db).await.unwrap();
        let db = Arc::new(db);
        NewspeakService {
            users: Arc::new(Mutex::new(HashMap::new())),
            server_store: ServerStore::new(db),
            auth_challenges: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[tokio::test]
    async fn register_persists_keys() {
        let svc = test_service().await;
        let request = RegisterRequest {
            username: "alice".to_string(),
            identity_key: vec![1, 2, 3],
            signed_prekey: Some(sample_prekey(KeyKind::X25519, &[4, 5], &[6])),
            one_time_prekeys: vec![sample_prekey_with_id(KeyKind::X25519, &[7], &[8], 1)],
            kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[9], &[10])),
        };

        let response = svc.register(Request::new(request)).await.unwrap();
        assert_eq!(response.into_inner().auth_challenge.len(), 32);

        let counts = svc.server_store.count_users_and_prekeys().await.unwrap();
        assert_eq!(counts, (1, 1));
    }

    #[tokio::test]
    async fn register_rejects_duplicate_username() {
        let svc = test_service().await;
        let request = RegisterRequest {
            username: "bob".to_string(),
            identity_key: vec![11, 12],
            signed_prekey: Some(sample_prekey(KeyKind::X25519, &[13], &[14])),
            one_time_prekeys: vec![],
            kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[15], &[16])),
        };

        svc.register(Request::new(request.clone())).await.unwrap();
        let err = svc.register(Request::new(request)).await.unwrap_err();
        assert_eq!(err.code(), Code::AlreadyExists);
    }

    #[tokio::test]
    async fn fetch_prekey_bundle_returns_and_consumes_keys() {
        let svc = test_service().await;
        let request = RegisterRequest {
            username: "carol".to_string(),
            identity_key: vec![1],
            signed_prekey: Some(sample_prekey(KeyKind::X25519, &[2], &[3])),
            one_time_prekeys: vec![sample_prekey_with_id(KeyKind::X25519, &[4], &[5], 7)],
            kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[6], &[7])),
        };

        svc.register(Request::new(request)).await.unwrap();

        let kem_prekey = sample_prekey(KeyKind::MlKem1024, &[8], &[9]);
        let user = svc
            .server_store
            .get_user("carol".to_string())
            .await
            .unwrap();
        let user_id = user.id.unwrap();
        svc.server_store
            .add_one_time_prekeys(user_id, Vec::<StoredPrekey>::new(), vec![kem_prekey])
            .await
            .unwrap();

        let response = svc
            .fetch_prekey_bundle(Request::new(FetchPrekeyBundleRequest {
                username: "carol".to_string(),
            }))
            .await
            .unwrap();

        let bundle = response.into_inner().bundle.unwrap();
        assert_eq!(bundle.identity_key, vec![1]);
        assert_eq!(bundle.signed_prekey.unwrap().key, vec![2]);
        assert_eq!(bundle.kem_encap_key.unwrap().key, vec![8]);
        assert_eq!(bundle.one_time_prekey.unwrap().key, vec![4]);

        let counts = svc.server_store.count_one_time_keys().await.unwrap();

        assert_eq!(counts, (0, 0));
    }

    #[tokio::test]
    async fn one_time_prekey_ids_are_scoped_per_user() {
        let svc = test_service().await;
        let alice_id = 42u32;
        let bob_id = 42u32;

        let alice_request = RegisterRequest {
            username: "alice".to_string(),
            identity_key: vec![10],
            signed_prekey: Some(sample_prekey(KeyKind::X25519, &[11], &[12])),
            one_time_prekeys: vec![sample_prekey_with_id(
                KeyKind::X25519,
                &[13],
                &[14],
                alice_id,
            )],
            kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[15], &[16])),
        };
        svc.register(Request::new(alice_request)).await.unwrap();

        let bob_request = RegisterRequest {
            username: "bob".to_string(),
            identity_key: vec![20],
            signed_prekey: Some(sample_prekey(KeyKind::X25519, &[21], &[22])),
            one_time_prekeys: vec![sample_prekey_with_id(
                KeyKind::X25519,
                &[23],
                &[24],
                bob_id,
            )],
            kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[25], &[26])),
        };
        svc.register(Request::new(bob_request)).await.unwrap();

        let alice_bundle = svc
            .fetch_prekey_bundle(Request::new(FetchPrekeyBundleRequest {
                username: "alice".to_string(),
            }))
            .await
            .unwrap()
            .into_inner()
            .bundle
            .unwrap();
        assert_eq!(alice_bundle.one_time_prekey_id, Some(alice_id));
        assert_eq!(alice_bundle.one_time_prekey.unwrap().key, vec![13]);

        let bob_bundle = svc
            .fetch_prekey_bundle(Request::new(FetchPrekeyBundleRequest {
                username: "bob".to_string(),
            }))
            .await
            .unwrap()
            .into_inner()
            .bundle
            .unwrap();
        assert_eq!(bob_bundle.one_time_prekey_id, Some(bob_id));
        assert_eq!(bob_bundle.one_time_prekey.unwrap().key, vec![23]);
    }

    #[tokio::test]
    async fn auth_challenge_verifies_and_is_single_use() {
        let svc = test_service().await;
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let request = RegisterRequest {
            username: "dave".to_string(),
            identity_key: signing_key.verifying_key().to_bytes().to_vec(),
            signed_prekey: Some(sample_prekey(KeyKind::X25519, &[1], &[2])),
            one_time_prekeys: vec![],
            kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[3], &[4])),
        };

        let response = svc.register(Request::new(request)).await.unwrap();
        let challenge: [u8; 32] = response
            .into_inner()
            .auth_challenge
            .as_slice()
            .try_into()
            .unwrap();
        let signature = signing_key.sign(&challenge);

        svc.verify_auth_challenge("dave".to_string(), signature)
            .await
            .unwrap();

        let err = svc
            .verify_auth_challenge("dave".to_string(), signing_key.sign(&challenge))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn auth_challenge_expires() {
        let svc = test_service().await;
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let request = RegisterRequest {
            username: "erin".to_string(),
            identity_key: signing_key.verifying_key().to_bytes().to_vec(),
            signed_prekey: Some(sample_prekey(KeyKind::X25519, &[5], &[6])),
            one_time_prekeys: vec![],
            kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[7], &[8])),
        };

        let response = svc.register(Request::new(request)).await.unwrap();
        let challenge_bytes = response.into_inner().auth_challenge;

        {
            let mut guard = svc.auth_challenges.lock().await;
            let challenge = guard.get("erin").cloned().unwrap();
            guard.insert(
                "erin".to_string(),
                AuthChallenge {
                    created_at: challenge.created_at
                        - (AUTH_CHALLENGE_TTL + Duration::from_secs(1)),
                    data: challenge.data,
                },
            );
        }

        let signature = signing_key.sign(&challenge_bytes);
        let err = svc
            .verify_auth_challenge("erin".to_string(), signature)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);

        let guard = svc.auth_challenges.lock().await;
        assert!(!guard.contains_key("erin"));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:10000".parse()?;
    let db = Connection::open("server_newspeak.db").await?;
    init_db(&db).await?;
    let db = Arc::new(db);
    let svc = NewspeakService {
        users: Arc::new(Mutex::new(HashMap::new())),
        server_store: ServerStore::new(db),
        auth_challenges: Arc::new(Mutex::new(HashMap::new())),
    };

    println!("NewspeakServer listening on {}", addr);

    Server::builder()
        .add_service(NewspeakServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
