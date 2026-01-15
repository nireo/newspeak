use blake3;
use sqlx::{self, Row, Sqlite, SqlitePool};
use tonic::Status;

use crate::newspeak::{PrekeyBundle, SignedPrekey};

/// OfflineMessageKind represents the type of offline message
#[derive(Debug, Clone, Copy)]
pub enum OfflineMessageKind {
    KeyExchange = 1,
    Regular = 2,
}

/// StoredPrekey represents a prekey stored in the database
#[derive(Debug)]
pub struct StoredPrekey {
    pub id: i64,
    pub prekey: SignedPrekey,
}

/// StoredOfflineMessage represents an offline message stored in the database
pub struct StoredOfflineMessage {
    pub id: i64,
    pub message: Vec<u8>,
    pub created_at: i64,
}

/// ServerUser represents a user stored in the server database
#[derive(Debug)]
pub struct ServerUser {
    pub id: Option<i64>,
    pub username: String,
    pub identity_key: Vec<u8>,
    pub signed_prekey: SignedPrekey,
    pub kem_prekey: SignedPrekey,
    pub one_time_prekeys: Vec<StoredPrekey>,
}

/// ServerStore represents the server-side storage for users and messages
#[derive(Clone)]
pub struct ServerStore {
    pub db: SqlitePool,
}

/// PrekeyTable represents the table for one-time prekeys or one-time KEM keys in the database
#[derive(Clone, Copy)]
enum PrekeyTable {
    OneTimePrekeys,
    OneTimeKemKeys,
}

impl PrekeyTable {
    fn name(self) -> &'static str {
        match self {
            PrekeyTable::OneTimePrekeys => "one_time_prekeys",
            PrekeyTable::OneTimeKemKeys => "one_time_kem_keys",
        }
    }
}

impl ServerStore {
    pub fn new(db: SqlitePool) -> Self {
        Self { db }
    }

    /// insert_user inserts a new user into the database
    pub async fn insert_user(&self, user: ServerUser) -> Result<(), Status> {
        let mut tx = self.db.begin().await.map_err(map_db_error)?;
        let result = sqlx::query(
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
        )
        .bind(&user.username)
        .bind(&user.identity_key)
        .bind(user.signed_prekey.kind)
        .bind(&user.signed_prekey.key)
        .bind(&user.signed_prekey.signature)
        .bind(user.kem_prekey.kind)
        .bind(&user.kem_prekey.key)
        .bind(&user.kem_prekey.signature)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let user_id = result.last_insert_rowid();

        for prekey in user.one_time_prekeys {
            let _ = insert_one_time_key(
                &mut tx,
                PrekeyTable::OneTimePrekeys,
                user_id,
                prekey.id,
                &prekey.prekey,
            )
            .await
            .map_err(map_db_error)?;
        }
        tx.commit().await.map_err(map_db_error)?;
        Ok(())
    }

    /// get_user retrieves a user from the database by username returns an error if none is found
    pub async fn get_user(&self, username: String) -> Result<ServerUser, Status> {
        let row = sqlx::query(
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
        )
        .bind(&username)
        .fetch_optional(&self.db)
        .await
        .map_err(map_db_error)?;

        let Some(row) = row else {
            return Err(Status::not_found("username not registered"));
        };

        let user_id: i64 = row.get(0);
        let identity_key: Vec<u8> = row.get(1);
        let signed_prekey_kind: i32 = row.get(2);
        let signed_prekey_key: Vec<u8> = row.get(3);
        let signed_prekey_signature: Vec<u8> = row.get(4);
        let kem_prekey_kind: i32 = row.get(5);
        let kem_prekey_key: Vec<u8> = row.get(6);
        let kem_prekey_signature: Vec<u8> = row.get(7);

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
            one_time_prekeys: Vec::new(),
        })
    }

    /// insert_message inserts an offline message into the database for the given receiver we store
    /// the bytes encoded using protobuf to make it easier and just based on the 'msg_kind' we can
    /// correctly decode the msg_data.
    pub async fn insert_message(
        &self,
        msg_kind: OfflineMessageKind,
        msg_data: &[u8],
        sender_username: &str,
        receiver_username: &str,
        created_at: i64,
    ) -> Result<(), Status> {
        let mut tx = self.db.begin().await.map_err(map_db_error)?;

        sqlx::query(
            "INSERT INTO offline_messages (
                sender_username,
                receiver_username,
                message,
                message_kind,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(sender_username)
        .bind(receiver_username)
        .bind(msg_data)
        .bind(msg_kind as i32)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;

        Ok(())
    }

    /// delete offline messages received before or at the given timestamp we cannot really delete
    /// the messages after returning them to the client because if the client crashes or fails to
    /// ack them we would lose messages.
    pub async fn delete_offline_message(
        &self,
        receiver_username: &str,
        received_timestamp: i64,
    ) -> Result<(), Status> {
        let mut tx = self.db.begin().await.map_err(map_db_error)?;

        sqlx::query(
            "DELETE FROM offline_messages
            WHERE receiver_username = ?1
            AND created_at <= ?2",
        )
        .bind(receiver_username)
        .bind(received_timestamp)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        Ok(())
    }

    /// get_offline_messages retrieves all offline messages for the given username ordered by
    /// creation time. we don't mark them as delivered or delete them here, that is the client's
    /// responsibility after receiving them. this is done to avoid losing messages if something
    /// goes wrong during delivery.
    pub async fn get_offline_messages(
        &self,
        username: &str,
    ) -> Result<Vec<StoredOfflineMessage>, Status> {
        let mut tx = self.db.begin().await.map_err(map_db_error)?;

        let rows = sqlx::query(
            "SELECT id, message, created_at
            FROM offline_messages
            WHERE receiver_username = ?1
            ORDER BY created_at ASC, id ASC",
        )
        .bind(username)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let mut messages = Vec::new();
        for row in rows {
            let id: i64 = row.get(0);
            let message: Vec<u8> = row.get(1);
            let created_at: i64 = row.get(2);
            messages.push(StoredOfflineMessage {
                id,
                message,
                created_at,
            });
        }

        tx.commit().await.map_err(map_db_error)?;
        Ok(messages)
    }

    /// fetch_prekey_bundle retrieves the prekey bundle for the given username this is needed for
    /// the key exchange process as the server is responsible for storing the given keys here.
    /// Currently it only picks one one-time prekey and one one-time KEM key from the database by
    /// the lowest ID.
    ///
    /// TODO: how to prevent missuse of this function?
    pub async fn fetch_prekey_bundle(&self, username: String) -> Result<PrekeyBundle, Status> {
        let mut tx = self.db.begin().await.map_err(map_db_error)?;
        let row = sqlx::query(
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
        )
        .bind(&username)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let Some(row) = row else {
            return Err(Status::not_found("username not registered"));
        };

        let user_id: i64 = row.get(0);
        let identity_key: Vec<u8> = row.get(1);
        let signed_prekey_kind: i32 = row.get(2);
        let signed_prekey_key: Vec<u8> = row.get(3);
        let signed_prekey_signature: Vec<u8> = row.get(4);
        let kem_prekey_kind: i32 = row.get(5);
        let kem_prekey_key: Vec<u8> = row.get(6);
        let kem_prekey_signature: Vec<u8> = row.get(7);
        let signed_prekey = SignedPrekey {
            kind: signed_prekey_kind,
            key: signed_prekey_key,
            signature: signed_prekey_signature,
            id: 0,
        };
        let kem_prekey = SignedPrekey {
            kind: kem_prekey_kind,
            key: kem_prekey_key,
            signature: kem_prekey_signature,
            id: 0,
        };

        let kem_encap_key = take_one_time_key(&mut tx, PrekeyTable::OneTimeKemKeys, user_id)
            .await
            .map_err(map_db_error)?;
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
        let one_time_prekey = take_one_time_key(&mut tx, PrekeyTable::OneTimePrekeys, user_id)
            .await
            .map_err(map_db_error)?;
        let (one_time_prekey, one_time_prekey_id) = match one_time_prekey {
            Some(prekey) => (Some(prekey.prekey), Some(prekey.id as u32)),
            None => (None, None),
        };

        tx.commit().await.map_err(map_db_error)?;

        Ok(PrekeyBundle {
            identity_key,
            signed_prekey: Some(signed_prekey),
            kem_encap_key: Some(kem_encap_key),
            one_time_prekey,
            kem_id,
            one_time_prekey_id,
        })
    }

    pub async fn add_one_time_prekeys(
        &self,
        user_id: i64,
        prekeys: Vec<StoredPrekey>,
        kem_prekeys: Vec<SignedPrekey>,
    ) -> Result<i32, Status> {
        let mut tx = self.db.begin().await.map_err(map_db_error)?;
        let mut count = 0;
        count += insert_one_time_keys(&mut tx, PrekeyTable::OneTimePrekeys, user_id, prekeys)
            .await
            .map_err(map_db_error)?;
        let kem_prekeys = kem_prekeys
            .into_iter()
            .map(|prekey| StoredPrekey {
                id: kem_db_id_from_key(&prekey.key),
                prekey,
            })
            .collect();
        count += insert_one_time_keys(&mut tx, PrekeyTable::OneTimeKemKeys, user_id, kem_prekeys)
            .await
            .map_err(map_db_error)?;
        tx.commit().await.map_err(map_db_error)?;
        Ok(count)
    }
}

async fn insert_one_time_key(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    table: PrekeyTable,
    user_id: i64,
    id: i64,
    prekey: &SignedPrekey,
) -> Result<i32, sqlx::Error> {
    let sql = format!(
        "INSERT OR IGNORE INTO {} (
            id,
            user_id,
            kind,
            key,
            signature
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        table.name()
    );

    let rows = sqlx::query(&sql)
        .bind(id)
        .bind(user_id)
        .bind(prekey.kind)
        .bind(&prekey.key)
        .bind(&prekey.signature)
        .execute(&mut **tx)
        .await?;
    Ok(i32::try_from(rows.rows_affected()).unwrap_or(0))
}

async fn insert_one_time_keys(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    table: PrekeyTable,
    user_id: i64,
    prekeys: Vec<StoredPrekey>,
) -> Result<i32, sqlx::Error> {
    let mut count = 0;
    for prekey in prekeys {
        count += insert_one_time_key(tx, table, user_id, prekey.id, &prekey.prekey).await?;
    }
    Ok(count)
}

async fn take_one_time_key(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    table: PrekeyTable,
    user_id: i64,
) -> Result<Option<StoredPrekey>, sqlx::Error> {
    let sql = format!(
        "SELECT id, kind, key, signature
        FROM {}
        WHERE user_id = ?1
        ORDER BY id
        LIMIT 1",
        table.name()
    );

    let row = sqlx::query(&sql)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?;

    if let Some(row) = row {
        let id: i64 = row.get(0);
        let kind: i32 = row.get(1);
        let key: Vec<u8> = row.get(2);
        let signature: Vec<u8> = row.get(3);
        let prekey_id = u32::try_from(id).unwrap_or(0);
        let prekey = SignedPrekey {
            kind,
            key,
            signature,
            id: prekey_id,
        };
        let delete_sql = format!(
            "DELETE FROM {} WHERE id = ?1 AND user_id = ?2",
            table.name()
        );
        sqlx::query(&delete_sql)
            .bind(id)
            .bind(user_id)
            .execute(&mut **tx)
            .await?;
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

fn map_db_error(err: sqlx::Error) -> Status {
    match err {
        sqlx::Error::Database(db_err) => {
            let code = db_err.code().map(|code| code.to_string());
            if code.as_deref() == Some("2067")
                || db_err
                    .message()
                    .contains("UNIQUE constraint failed: users.username")
            {
                Status::already_exists("username already registered")
            } else {
                Status::internal(format!("database error: {}", db_err.message()))
            }
        }
        _ => Status::internal(format!("database error: {}", err)),
    }
}

pub async fn init_db(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
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
        );",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS one_time_prekeys (
            id INTEGER,
            user_id INTEGER,
            kind INTEGER NOT NULL,
            key BLOB NOT NULL,
            signature BLOB NOT NULL,
            created_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (id, user_id)
        );",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS offline_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_username TEXT NOT NULL,
            receiver_username TEXT NOT NULL,
            message BLOB NOT NULL,
            message_kind INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS one_time_kem_keys (
            id INTEGER,
            user_id INTEGER,
            kind INTEGER NOT NULL,
            key BLOB NOT NULL,
            signature BLOB NOT NULL,
            created_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (id, user_id)
        );",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
impl ServerStore {
    pub async fn count_users_and_prekeys(&self) -> Result<(i64, i64), Status> {
        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.db)
            .await
            .map_err(map_db_error)?;
        let prekey_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM one_time_prekeys")
            .fetch_one(&self.db)
            .await
            .map_err(map_db_error)?;
        let counts = (user_count, prekey_count);
        Ok(counts)
    }

    pub async fn count_one_time_keys(&self) -> Result<(i64, i64), Status> {
        let prekey_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM one_time_prekeys")
            .fetch_one(&self.db)
            .await
            .map_err(map_db_error)?;
        let kem_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM one_time_kem_keys")
            .fetch_one(&self.db)
            .await
            .map_err(map_db_error)?;
        let counts = (prekey_count, kem_count);
        Ok(counts)
    }
}
