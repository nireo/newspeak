use anyhow::{Result, anyhow};
use std::path::Path;

use ed25519_dalek::Signer;
use ml_kem::{Encoded, EncodedSizeUser, MlKem1024Params, kem::DecapsulationKey};
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection, SqlitePoolOptions};
use sqlx::{Row, Sqlite, SqlitePool};
use x25519_dalek as x25519;

use crate::pqxdh;
use crate::pqxdh::KemId;
use crate::pqxdh::KeyStore;
use crate::pqxdh::SignedMlKemPrekey;
use crate::pqxdh::SignedPrekey;
use crate::ratchet::RatchetState;

pub struct ConversationMessage {
    pub content: String,
    pub is_sender: bool,
    pub timestamp: i64,
}

pub struct PeerIdentity {
    pub identity_key: [u8; 32],
    pub verified: bool,
}

pub enum PeerIdentityStoreResult {
    Inserted,
    ExistingMatch { verified: bool },
    ExistingMismatch,
}

#[derive(Clone)]
pub struct LocalStorage {
    db: SqlitePool,
}

struct StoredUser {
    identity_sk: [u8; 32],
    signed_prekey_sk: [u8; 32],
    kem_decap: Vec<u8>,
    kem_store: KeyStore<KemId, SignedMlKemPrekey>,
    ec_store: KeyStore<u32, SignedPrekey>,
}

type SqliteQuery<'a> = sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>>;

enum LocalKeyTable {
    Kem,
    Ec,
}

impl LocalKeyTable {
    fn name(&self) -> &'static str {
        match self {
            LocalKeyTable::Kem => "kem_keys",
            LocalKeyTable::Ec => "ec_keys",
        }
    }

    fn key_column(&self) -> &'static str {
        match self {
            LocalKeyTable::Kem => "decap",
            LocalKeyTable::Ec => "sk",
        }
    }
}

enum LocalKeyId {
    Blob(Vec<u8>),
    Int(i64),
}

impl LocalKeyId {
    fn bind<'a>(&'a self, query: SqliteQuery<'a>) -> SqliteQuery<'a> {
        match self {
            LocalKeyId::Blob(val) => query.bind(val.as_slice()),
            LocalKeyId::Int(val) => query.bind(*val),
        }
    }
}

impl LocalStorage {
    async fn insert_key_rows(
        connection: &mut SqliteConnection,
        username: &str,
        rows: Vec<(LocalKeyId, Vec<u8>, i64)>,
        table: LocalKeyTable,
    ) -> Result<()> {
        let sql = format!(
            "INSERT INTO {} (
                id,
                username,
                {},
                used
            ) VALUES (?1, ?2, ?3, ?4)",
            table.name(),
            table.key_column()
        );

        for (id, key_bytes, used) in rows {
            let query = sqlx::query(&sql);
            let query = id.bind(query).bind(username).bind(key_bytes).bind(used);
            query.execute(&mut *connection).await?;
        }
        Ok(())
    }

    async fn mark_key_used(
        &self,
        username: &str,
        id: LocalKeyId,
        table: LocalKeyTable,
    ) -> Result<()> {
        let username = username.to_string();
        let sql = format!(
            "UPDATE {}
             SET used = 1
             WHERE username = ?1 AND id = ?2",
            table.name()
        );

        let query = sqlx::query(&sql).bind(&username);
        let query = id.bind(query);
        query.execute(&self.db).await?;
        Ok(())
    }

    pub async fn new(username: &str) -> Result<Self> {
        Self::new_with_path(format!("{}_newspeak.db", username)).await
    }

    pub async fn new_with_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .foreign_keys(true);
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        Self::init_migrations(&db).await?;

        Ok(LocalStorage { db })
    }

    pub async fn load_or_create_user(&self, username: &str) -> Result<pqxdh::KeyExchangeUser> {
        if username.is_empty() {
            return Err(anyhow!("username is required"));
        }

        if let Some(stored) = self.load_user(username).await? {
            return stored_user_to_key_exchange_user(stored);
        }

        let user = pqxdh::KeyExchangeUser::new();

        self.insert_user(username, &user).await?;
        Ok(user)
    }

    async fn load_user(&self, username: &str) -> Result<Option<StoredUser>> {
        let username_owned = username.to_string();
        let row = sqlx::query(
            "SELECT identity_sk, signed_prekey_sk, kem_decap
             FROM local_users
             WHERE username = ?1",
        )
        .bind(&username_owned)
        .fetch_optional(&self.db)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let identity_sk: Vec<u8> = row.get(0);
        let signed_prekey_sk: Vec<u8> = row.get(1);
        let kem_decap: Vec<u8> = row.get(2);

        let kem_store = self.get_user_kem_keys(username).await?;
        let ec_store = self.get_user_ec_keys(username).await?;

        Ok(Some(StoredUser {
            identity_sk: bytes_to_32(&identity_sk)?,
            signed_prekey_sk: bytes_to_32(&signed_prekey_sk)?,
            kem_decap,
            kem_store,
            ec_store,
        }))
    }

    async fn load_identity_sk(&self, username: &str) -> Result<Option<[u8; 32]>> {
        let username = username.to_string();
        let row = sqlx::query(
            "SELECT identity_sk
             FROM local_users
             WHERE username = ?1",
        )
        .bind(&username)
        .fetch_optional(&self.db)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let identity_sk: Vec<u8> = row.get(0);

        Ok(Some(bytes_to_32(&identity_sk)?))
    }

    async fn insert_user(&self, username: &str, user: &pqxdh::KeyExchangeUser) -> Result<()> {
        let identity_sk = user.identity_sk.as_bytes();
        let signed_prekey_sk = user.signed_prekey.private_key.to_bytes();
        let kem_decap = user.last_resort_kem.decap_key.as_bytes();

        let mut tx = self.db.begin().await?;
        sqlx::query(
            "INSERT INTO local_users (
                username,
                identity_sk,
                signed_prekey_sk,
                kem_decap
            ) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(username)
        .bind(identity_sk.as_slice())
        .bind(signed_prekey_sk.as_slice())
        .bind(kem_decap.as_slice())
        .execute(&mut *tx)
        .await?;

        Self::insert_key_rows(
            &mut tx,
            username,
            Self::kem_key_rows(&user.one_time_kem_keys),
            LocalKeyTable::Kem,
        )
        .await?;
        Self::insert_key_rows(
            &mut tx,
            username,
            Self::ec_key_rows(&user.one_time_keys),
            LocalKeyTable::Ec,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    fn kem_key_rows(
        keys: &pqxdh::KeyStore<pqxdh::KemId, pqxdh::SignedMlKemPrekey>,
    ) -> Vec<(LocalKeyId, Vec<u8>, i64)> {
        keys.iter()
            .map(|(id, key, used)| {
                (
                    LocalKeyId::Blob(id.to_vec()),
                    key.decap_key.as_bytes().as_slice().to_vec(),
                    i64::from(used),
                )
            })
            .collect()
    }

    fn ec_key_rows(
        keys: &pqxdh::KeyStore<u32, pqxdh::SignedPrekey>,
    ) -> Vec<(LocalKeyId, Vec<u8>, i64)> {
        keys.iter()
            .map(|(id, key, used)| {
                (
                    LocalKeyId::Int(i64::from(*id)),
                    key.private_key.as_bytes().to_vec(),
                    i64::from(used),
                )
            })
            .collect()
    }

    #[cfg(test)]
    async fn insert_kem_keys(
        &self,
        username: &str,
        keys: &pqxdh::KeyStore<pqxdh::KemId, pqxdh::SignedMlKemPrekey>,
    ) -> Result<()> {
        let mut tx = self.db.begin().await?;
        Self::insert_key_rows(
            &mut tx,
            username,
            Self::kem_key_rows(keys),
            LocalKeyTable::Kem,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    #[cfg(test)]
    async fn insert_ec_keys(
        &self,
        username: &str,
        keys: &pqxdh::KeyStore<u32, pqxdh::SignedPrekey>,
    ) -> Result<()> {
        let mut tx = self.db.begin().await?;
        Self::insert_key_rows(
            &mut tx,
            username,
            Self::ec_key_rows(keys),
            LocalKeyTable::Ec,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_user_kem_keys(
        &self,
        username: &str,
    ) -> Result<KeyStore<KemId, SignedMlKemPrekey>> {
        let mut key_store = KeyStore::new();
        let Some(identity_sk_bytes) = self.load_identity_sk(username).await? else {
            return Ok(key_store);
        };
        let identity_sk = ed25519_dalek::SigningKey::from_bytes(&identity_sk_bytes);
        let username = username.to_string();
        let rows = sqlx::query(
            "SELECT id, decap, used
            FROM kem_keys
            WHERE username = ?1",
        )
        .bind(&username)
        .fetch_all(&self.db)
        .await?;

        for row in rows {
            let id_bytes: Vec<u8> = row.get(0);
            let decap: Vec<u8> = row.get(1);
            let used: i64 = row.get(2);
            let id = bytes_to_16(&id_bytes)?;
            let encoded = Encoded::<DecapsulationKey<MlKem1024Params>>::try_from(decap.as_slice())
                .map_err(|_| anyhow!("invalid kem decapsulation key length: {}", decap.len()))?;
            let decap_key = DecapsulationKey::from_bytes(&encoded);
            let encap_key = decap_key.encapsulation_key().clone();
            let signature = identity_sk.sign(&encap_key.as_bytes());
            let key = pqxdh::SignedMlKemPrekey {
                decap_key,
                encap_key,
                signature,
            };
            key_store.insert(id, key);
            if used != 0 {
                key_store.mark_used(&id);
            }
        }

        Ok(key_store)
    }

    pub async fn get_user_ec_keys(
        &self,
        username: &str,
    ) -> Result<KeyStore<u32, pqxdh::SignedPrekey>> {
        let mut key_store = KeyStore::new();
        let Some(identity_sk_bytes) = self.load_identity_sk(username).await? else {
            return Ok(key_store);
        };
        let identity_sk = ed25519_dalek::SigningKey::from_bytes(&identity_sk_bytes);
        let username = username.to_string();
        let rows = sqlx::query(
            "SELECT id, sk, used
            FROM ec_keys
            WHERE username = ?1",
        )
        .bind(&username)
        .fetch_all(&self.db)
        .await?;

        for row in rows {
            let id: i64 = row.get(0);
            let sk: Vec<u8> = row.get(1);
            let used: i64 = row.get(2);
            let id: u32 = id
                .try_into()
                .map_err(|_| anyhow!("invalid ec key id: {}", id))?;
            let sk_bytes: [u8; 32] = bytes_to_32(&sk)?;
            let private_key = x25519::StaticSecret::from(sk_bytes);
            let public_key = x25519::PublicKey::from(&private_key);
            let signature = identity_sk.sign(public_key.as_bytes());
            let key = pqxdh::SignedPrekey {
                private_key,
                public_key,
                signature,
            };
            key_store.insert(id, key);
            if used != 0 {
                key_store.mark_used(&id);
            }
        }

        Ok(key_store)
    }

    pub async fn mark_ec_key_used(&self, username: &str, id: u32) -> Result<()> {
        self.mark_key_used(username, LocalKeyId::Int(i64::from(id)), LocalKeyTable::Ec)
            .await
    }

    pub async fn mark_kem_key_used(&self, username: &str, id: &KemId) -> Result<()> {
        self.mark_key_used(username, LocalKeyId::Blob(id.to_vec()), LocalKeyTable::Kem)
            .await
    }

    pub async fn get_conversation(
        &self,
        username: &str,
        peer: &str,
    ) -> Result<Option<RatchetState>> {
        let username = username.to_string();
        let peer = peer.to_string();
        let row = sqlx::query(
            "SELECT ratchet_state
             FROM conversations
             WHERE username = ?1 AND peer = ?2",
        )
        .bind(&username)
        .bind(&peer)
        .fetch_optional(&self.db)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let ratchet_state: Vec<u8> = row.get(0);

        Ok(Some(serde_json::from_slice(&ratchet_state)?))
    }

    pub async fn update_conversation(
        &self,
        username: &str,
        peer: &str,
        ratchet_state: &RatchetState,
    ) -> Result<()> {
        let ratchet_state = serde_json::to_vec(ratchet_state)?;
        let username = username.to_string();
        let peer = peer.to_string();

        sqlx::query(
            "INSERT INTO conversations (
                username,
                peer,
                ratchet_state
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(username, peer)
            DO UPDATE SET ratchet_state = excluded.ratchet_state",
        )
        .bind(&username)
        .bind(&peer)
        .bind(&ratchet_state)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    pub async fn add_message(
        &self,
        username: &str,
        peer: &str,
        content: &str,
        is_sender: bool,
        timestamp: i64,
    ) -> Result<()> {
        let conversation_id = self
            .get_conversation_id(username, peer)
            .await?
            .ok_or_else(|| anyhow!("conversation not found"))?;
        let content = content.to_string();
        let is_sender = if is_sender { 1 } else { 0 };

        sqlx::query(
            "INSERT INTO messages (
                conversation_id,
                content,
                is_sender,
                timestamp
            ) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(conversation_id)
        .bind(&content)
        .bind(is_sender)
        .bind(timestamp)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    pub async fn get_conversation_messages(
        &self,
        username: &str,
        peer: &str,
    ) -> Result<Vec<ConversationMessage>> {
        let Some(conversation_id) = self.get_conversation_id(username, peer).await? else {
            return Ok(Vec::new());
        };
        let rows = sqlx::query(
            "SELECT content, is_sender, timestamp
             FROM messages
             WHERE conversation_id = ?1
             ORDER BY id ASC",
        )
        .bind(conversation_id)
        .fetch_all(&self.db)
        .await?;

        let messages = rows
            .into_iter()
            .map(|row| {
                let content: String = row.get(0);
                let is_sender: i64 = row.get(1);
                let timestamp: i64 = row.get(2);
                ConversationMessage {
                    content,
                    is_sender: is_sender != 0,
                    timestamp,
                }
            })
            .collect();

        Ok(messages)
    }

    async fn get_conversation_id(&self, username: &str, peer: &str) -> Result<Option<i64>> {
        let username = username.to_string();
        let peer = peer.to_string();
        let row = sqlx::query(
            "SELECT id
             FROM conversations
             WHERE username = ?1 AND peer = ?2",
        )
        .bind(&username)
        .bind(&peer)
        .fetch_optional(&self.db)
        .await?;

        Ok(row.map(|row| row.get(0)))
    }

    pub async fn get_user_conversations(&self, username: &str) -> Result<Vec<String>> {
        let username = username.to_string();
        let rows = sqlx::query(
            "SELECT peer
             FROM conversations
             WHERE username = ?1",
        )
        .bind(&username)
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    pub async fn get_peer_identity(
        &self,
        username: &str,
        peer: &str,
    ) -> Result<Option<PeerIdentity>> {
        let username = username.to_string();
        let peer = peer.to_string();
        let row = sqlx::query(
            "SELECT identity_key, verified
             FROM peer_identities
             WHERE username = ?1 AND peer = ?2",
        )
        .bind(&username)
        .bind(&peer)
        .fetch_optional(&self.db)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let identity_key: Vec<u8> = row.get(0);
        let verified: i64 = row.get(1);

        Ok(Some(PeerIdentity {
            identity_key: bytes_to_32(&identity_key)?,
            verified: verified != 0,
        }))
    }

    pub async fn store_peer_identity(
        &self,
        username: &str,
        peer: &str,
        identity_key: &[u8],
    ) -> Result<PeerIdentityStoreResult> {
        let identity_key = bytes_to_32(identity_key)?;
        if let Some(existing) = self.get_peer_identity(username, peer).await? {
            if existing.identity_key != identity_key {
                return Ok(PeerIdentityStoreResult::ExistingMismatch);
            }
            return Ok(PeerIdentityStoreResult::ExistingMatch {
                verified: existing.verified,
            });
        }

        let username = username.to_string();
        let peer = peer.to_string();
        sqlx::query(
            "INSERT INTO peer_identities (
                username,
                peer,
                identity_key,
                verified
            ) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&username)
        .bind(&peer)
        .bind(identity_key.as_slice())
        .bind(0i64)
        .execute(&self.db)
        .await?;

        Ok(PeerIdentityStoreResult::Inserted)
    }

    pub async fn mark_peer_identity_verified(&self, username: &str, peer: &str) -> Result<bool> {
        let username = username.to_string();
        let peer = peer.to_string();
        let result = sqlx::query(
            "UPDATE peer_identities
             SET verified = 1
             WHERE username = ?1 AND peer = ?2",
        )
        .bind(&username)
        .bind(&peer)
        .execute(&self.db)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn init_migrations(pool: &SqlitePool) -> Result<()> {
        sqlx::migrate!("./migrations/local").run(pool).await?;
        Ok(())
    }
}

fn stored_user_to_key_exchange_user(stored: StoredUser) -> Result<pqxdh::KeyExchangeUser> {
    let identity_sk = ed25519_dalek::SigningKey::from_bytes(&stored.identity_sk);
    let identity_pk = identity_sk.verifying_key();

    let signed_prekey_sk = x25519::StaticSecret::from(stored.signed_prekey_sk);
    let signed_prekey_pk = x25519::PublicKey::from(&signed_prekey_sk);
    let signed_prekey_sig = identity_sk.sign(signed_prekey_pk.as_bytes());
    let signed_prekey = pqxdh::SignedPrekey {
        private_key: signed_prekey_sk,
        public_key: signed_prekey_pk,
        signature: signed_prekey_sig,
    };

    let encoded =
        Encoded::<DecapsulationKey<MlKem1024Params>>::try_from(stored.kem_decap.as_slice())
            .map_err(|_| {
                anyhow!(
                    "invalid kem decapsulation key length: {}",
                    stored.kem_decap.len()
                )
            })?;
    let decap_key = DecapsulationKey::from_bytes(&encoded);
    let encap_key = decap_key.encapsulation_key().clone();
    let kem_sig = identity_sk.sign(&encap_key.as_bytes());
    let last_resort_kem = pqxdh::SignedMlKemPrekey {
        decap_key,
        encap_key,
        signature: kem_sig,
    };

    let one_time_keys = stored.ec_store;
    let one_time_kem_keys = stored.kem_store;
    let one_time_prekey_id = one_time_keys
        .iter()
        .map(|(id, _, _)| *id)
        .max()
        .map(|id| id.saturating_add(1))
        .unwrap_or(0);
    let last_resort_id = pqxdh::kem_id_from_key(last_resort_kem.encap_key.as_bytes().as_slice());

    Ok(pqxdh::KeyExchangeUser {
        identity_sk,
        identity_pk,
        signed_prekey,
        last_resort_kem,
        last_resort_id,
        one_time_keys,
        one_time_kem_keys,
        one_time_prekey_id,
    })
}

fn bytes_to_32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid key length: {}", bytes.len()))
}

fn bytes_to_16(bytes: &[u8]) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid key length: {}", bytes.len()))
}

#[cfg(test)]
#[path = "tests/local_store.rs"]
mod tests;
