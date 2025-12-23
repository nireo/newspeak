mod pqxdh;
mod ratchet;

pub mod newspeak {
    tonic::include_proto!("newspeak");
}

use newspeak::newspeak_server::{Newspeak, NewspeakServer};
use newspeak::{
    FetchPrekeyBundleRequest, FetchPrekeyBundleResponse, PrekeyBundle, RegisterRequest,
    RegisterResponse, SignedPrekey,
};
use blake3;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_rusqlite::Connection;
use tokio_rusqlite::Error as TokioRusqliteError;
use tokio_rusqlite::rusqlite::{self, Error as RusqliteError, OptionalExtension, params};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use crate::newspeak::{ClientMessage, ServerMessage};

#[derive(Clone)]
struct NewspeakService {
    db: Arc<Connection>,
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

                let user_row: Option<(i64, Vec<u8>, SignedPrekey)> = tx
                    .query_row(
                        "SELECT id, identity_key, signed_prekey_kind, signed_prekey_key, signed_prekey_signature
                        FROM users
                        WHERE username = ?1",
                        params![username],
                        |row| {
                            let user_id: i64 = row.get(0)?;
                            let identity_key: Vec<u8> = row.get(1)?;
                            let signed_prekey_kind: i32 = row.get(2)?;
                            let signed_prekey_key: Vec<u8> = row.get(3)?;
                            let signed_prekey_signature: Vec<u8> = row.get(4)?;
                            Ok((
                                user_id,
                                identity_key,
                                SignedPrekey {
                                    kind: signed_prekey_kind,
                                    key: signed_prekey_key,
                                    signature: signed_prekey_signature,
                                },
                            ))
                        },
                    )
                    .optional()?;

                let Some((user_id, identity_key, signed_prekey)) = user_row else {
                    return Ok(None);
                };

                let kem_encap_key = take_one_time_key(&tx, "one_time_kem_keys", user_id)?;
                if kem_encap_key.is_none() {
                    tx.commit()?;
                    return Ok(Some(PrekeyBundle {
                        identity_key,
                        signed_prekey: Some(signed_prekey),
                        kem_encap_key: None,
                        one_time_prekey: None,
                        kem_id: Vec::new(),
                        one_time_prekey_id: None,
                    }));
                }

                let kem_encap_key = kem_encap_key.unwrap();
                let kem_id = kem_id_from_key(&kem_encap_key.prekey.key);
                let one_time_prekey = take_one_time_key(&tx, "one_time_prekeys", user_id)?;
                let (one_time_prekey, one_time_prekey_id) = match one_time_prekey {
                    Some(prekey) => (Some(prekey.prekey), Some(prekey.id as u32)),
                    None => (None, None),
                };

                tx.commit()?;

                Ok(Some(PrekeyBundle {
                    identity_key,
                    signed_prekey: Some(signed_prekey),
                    kem_encap_key: Some(kem_encap_key.prekey),
                    one_time_prekey,
                    kem_id,
                    one_time_prekey_id,
                }))
            })
            .await
            .map_err(map_db_error)?;

        let bundle = bundle.ok_or_else(|| Status::not_found("username not registered"))?;
        if bundle.kem_encap_key.is_none() {
            return Err(Status::failed_precondition("kem prekey unavailable"));
        }

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

        tokio::spawn(async move {
            while let Some(message) = inbound.message().await.transpose() {
                match message {
                    Ok(client_message) => {
                        // TODO: convert ClientMessage -> ServerMessage and send over tx.
                        let _ = client_message;
                    }
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                }
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
                    signed_prekey_signature
                ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    username,
                    identity_key,
                    signed_prekey.kind,
                    signed_prekey.key,
                    signed_prekey.signature
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
        NewspeakService { db: Arc::new(db) }
    }

    #[tokio::test]
    async fn register_persists_keys() {
        let svc = test_service().await;
        let request = RegisterRequest {
            username: "alice".to_string(),
            identity_key: vec![1, 2, 3],
            signed_prekey: Some(sample_prekey(KeyKind::X25519, &[4, 5], &[6])),
            one_time_prekeys: vec![sample_prekey(KeyKind::X25519, &[7], &[8])],
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
        };

        svc.register(Request::new(request)).await.unwrap();

        let kem_prekey = sample_prekey(KeyKind::MlKem1024, &[6], &[7]);
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
        assert_eq!(bundle.kem_encap_key.unwrap().key, vec![6]);
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
    let svc = NewspeakService { db: Arc::new(db) };

    println!("NewspeakServer listening on {}", addr);

    Server::builder()
        .add_service(NewspeakServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
