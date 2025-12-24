pub mod newspeak {
    tonic::include_proto!("newspeak");
}

use blake3;
use newspeak::newspeak_server::{Newspeak, NewspeakServer};
use newspeak::{
    FetchPrekeyBundleRequest, FetchPrekeyBundleResponse, PrekeyBundle, RegisterRequest,
    RegisterResponse, SignedPrekey,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio_rusqlite::Connection;
use tokio_rusqlite::Error as TokioRusqliteError;
use tokio_rusqlite::rusqlite::{self, Error as RusqliteError, OptionalExtension, params};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use crate::newspeak::{ClientMessage, JoinResponse, ServerMessage, client_message, server_message};

#[derive(Clone)]
struct NewspeakService {
    db: Arc<Connection>,
    users: Arc<Mutex<HashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>>,
}

struct StoredPrekey {
    id: i64,
    prekey: SignedPrekey,
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

        let username = request.username;
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
                                },
                                SignedPrekey {
                                    kind: kem_prekey_kind,
                                    key: kem_prekey_key,
                                    signature: kem_prekey_signature,
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

        let bundle = bundle.ok_or_else(|| Status::not_found("username not registered"))?;

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
        let identity_key = request.identity_key;
        let one_time_prekeys = request.one_time_prekeys;
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
                    username,
                    identity_key,
                    signed_prekey.kind,
                    signed_prekey.key,
                    signed_prekey.signature,
                    kem_prekey.kind,
                    kem_prekey.key,
                    kem_prekey.signature
                ],
            )?;

            let user_id = tx.last_insert_rowid();

            for prekey in one_time_prekeys {
                insert_one_time_key(&tx, "one_time_prekeys", user_id, &prekey)?;
            }

            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(map_db_error)?;

        let reply = RegisterResponse {
            auth_challenge: Vec::new(),
        };
        Ok(Response::new(reply))
    }
}

fn insert_one_time_key(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    user_id: i64,
    prekey: &SignedPrekey,
) -> Result<(), RusqliteError> {
    let sql = format!(
        "INSERT INTO {} (
            user_id,
            kind,
            key,
            signature
        ) VALUES (?1, ?2, ?3, ?4)",
        table
    );

    tx.execute(
        &sql,
        params![user_id, prekey.kind, prekey.key, prekey.signature],
    )?;
    Ok(())
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
            Ok((
                id,
                SignedPrekey {
                    kind,
                    key,
                    signature,
                },
            ))
        })
        .optional()?;

    if let Some((id, prekey)) = row {
        let delete_sql = format!("DELETE FROM {} WHERE id = ?1", table);
        tx.execute(&delete_sql, params![id])?;
        Ok(Some(StoredPrekey { id, prekey }))
    } else {
        Ok(None)
    }
}

fn kem_id_from_key(key: &[u8]) -> Vec<u8> {
    blake3::hash(key).as_bytes()[..16].to_vec()
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                kind INTEGER NOT NULL,
                key BLOB NOT NULL,
                signature BLOB NOT NULL,
                created_at INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS one_time_kem_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                kind INTEGER NOT NULL,
                key BLOB NOT NULL,
                signature BLOB NOT NULL,
                created_at INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );",
        )?;
        Ok::<(), RusqliteError>(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use newspeak::KeyKind;
    use tonic::Code;

    fn sample_prekey(kind: KeyKind, key: &[u8], signature: &[u8]) -> SignedPrekey {
        SignedPrekey {
            kind: kind as i32,
            key: key.to_vec(),
            signature: signature.to_vec(),
        }
    }

    async fn test_service() -> NewspeakService {
        let db = Connection::open(":memory:").await.unwrap();
        init_db(&db).await.unwrap();
        NewspeakService {
            db: Arc::new(db),
            users: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[tokio::test]
    async fn register_persists_keys() {
        let svc = test_service().await;
        let request = RegisterRequest {
            username: "alice".to_string(),
            identity_key: vec![1, 2, 3],
            signed_prekey: Some(sample_prekey(KeyKind::X25519, &[4, 5], &[6])),
            one_time_prekeys: vec![sample_prekey(KeyKind::X25519, &[7], &[8])],
            kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[9], &[10])),
        };

        let response = svc.register(Request::new(request)).await.unwrap();
        assert!(response.into_inner().auth_challenge.is_empty());

        let counts = svc
            .db
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
            .unwrap();

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
            one_time_prekeys: vec![sample_prekey(KeyKind::X25519, &[4], &[5])],
            kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[6], &[7])),
        };

        svc.register(Request::new(request)).await.unwrap();

        let kem_prekey = sample_prekey(KeyKind::MlKem1024, &[8], &[9]);
        svc.db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let user_id: i64 = tx.query_row(
                    "SELECT id FROM users WHERE username = ?1",
                    params!["carol"],
                    |row| row.get(0),
                )?;
                insert_one_time_key(&tx, "one_time_kem_keys", user_id, &kem_prekey)?;
                tx.commit()?;
                Ok::<(), RusqliteError>(())
            })
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

        let counts = svc
            .db
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
            .unwrap();

        assert_eq!(counts, (0, 0));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:10000".parse()?;
    let db = Connection::open("newspeak.db").await?;
    init_db(&db).await?;
    let svc = NewspeakService {
        db: Arc::new(db),
        users: Arc::new(Mutex::new(HashMap::new())),
    };

    println!("NewspeakServer listening on {}", addr);

    Server::builder()
        .add_service(NewspeakServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
