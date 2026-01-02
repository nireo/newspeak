use anyhow::{Result, anyhow};
use std::path::Path;

use ed25519_dalek::Signer;
use ml_kem::{Encoded, EncodedSizeUser, MlKem1024Params, kem::DecapsulationKey};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
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
}

#[derive(Clone)]
pub struct LocalStorage {
    db: SqlitePool,
}

struct StoredUser {
    identity_sk: [u8; 32],
    signed_prekey_sk: [u8; 32],
    kem_decap: Vec<u8>,
    kem_store: Option<KeyStore<KemId, SignedMlKemPrekey>>,
    ec_store: Option<KeyStore<u32, SignedPrekey>>,
}

impl LocalStorage {
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
            kem_store: Some(kem_store),
            ec_store: Some(ec_store),
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
        let identity_sk = user.identity_sk.as_bytes().to_vec();
        let signed_prekey_sk = user.signed_prekey.private_key.to_bytes().to_vec();
        let kem_decap = user
            .last_resort_kem
            .decap_key
            .as_bytes()
            .as_slice()
            .to_vec();
        let username_owned = username.to_string();

        {
            let mut tx = self.db.begin().await?;
            sqlx::query(
                "INSERT INTO local_users (
                    username,
                    identity_sk,
                    signed_prekey_sk,
                    kem_decap
                ) VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&username_owned)
            .bind(&identity_sk)
            .bind(&signed_prekey_sk)
            .bind(&kem_decap)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }

        self.insert_kem_keys(&username, &user.one_time_kem_keys)
            .await?;
        self.insert_ec_keys(&username, &user.one_time_keys).await?;

        Ok(())
    }

    async fn insert_kem_keys(
        &self,
        username: &str,
        keys: &pqxdh::KeyStore<pqxdh::KemId, pqxdh::SignedMlKemPrekey>,
    ) -> Result<()> {
        if keys.len() == 0 {
            return Ok(());
        }
        let rows: Vec<(pqxdh::KemId, Vec<u8>, i64)> = keys
            .iter()
            .map(|(id, key, used)| {
                (
                    *id,
                    key.decap_key.as_bytes().as_slice().to_vec(),
                    if used { 1 } else { 0 },
                )
            })
            .collect();
        let username = username.to_string();

        {
            let mut tx = self.db.begin().await?;
            for (id, key_bytes, used) in rows {
                sqlx::query(
                    "INSERT INTO kem_keys (
                        id,
                        username,
                        decap,
                        used
                    ) VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(id.to_vec())
                .bind(&username)
                .bind(&key_bytes)
                .bind(used)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
        }

        Ok(())
    }

    async fn insert_ec_keys(
        &self,
        username: &str,
        keys: &pqxdh::KeyStore<u32, pqxdh::SignedPrekey>,
    ) -> Result<()> {
        if keys.len() == 0 {
            return Ok(());
        }
        let rows: Vec<(u32, Vec<u8>, i64)> = keys
            .iter()
            .map(|(id, key, used)| {
                (
                    *id,
                    key.private_key.as_bytes().to_vec(),
                    if used { 1 } else { 0 },
                )
            })
            .collect();
        let username = username.to_string();

        {
            let mut tx = self.db.begin().await?;
            for (id, key_bytes, used) in rows {
                sqlx::query(
                    "INSERT INTO ec_keys (
                        id,
                        username,
                        sk,
                        used
                    ) VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(id as i64)
                .bind(&username)
                .bind(&key_bytes)
                .bind(used)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
        }

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

        Ok(Some(ratchet_state_from_bytes(&ratchet_state)?))
    }

    pub async fn update_conversation(
        &self,
        username: &str,
        peer: &str,
        ratchet_state: &RatchetState,
    ) -> Result<()> {
        let ratchet_state = ratchet_state_to_bytes(ratchet_state);
        let username = username.to_string();
        let peer = peer.to_string();

        {
            let mut tx = self.db.begin().await?;
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
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }

        Ok(())
    }

    pub async fn add_message(
        &self,
        username: &str,
        peer: &str,
        content: &str,
        is_sender: bool,
    ) -> Result<()> {
        let conversation_id = self
            .get_conversation_id(username, peer)
            .await?
            .ok_or_else(|| anyhow!("conversation not found"))?;
        let content = content.to_string();
        let is_sender = if is_sender { 1 } else { 0 };

        {
            let mut tx = self.db.begin().await?;
            sqlx::query(
                "INSERT INTO messages (
                    conversation_id,
                    content,
                    is_sender
                ) VALUES (?1, ?2, ?3)",
            )
            .bind(conversation_id)
            .bind(&content)
            .bind(is_sender)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }

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
            "SELECT content, is_sender
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
                ConversationMessage {
                    content,
                    is_sender: is_sender != 0,
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

    async fn init_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
        // some thoughts on the schema: for a relational format it makes more sense to store the
        // user like this, overall sqlite is very reliable and a good also for internal storage in
        // my opinion.
        //
        // also having a blob as the kem key id seems quite weird, but it makes sense since they're
        // internally stored that way and there is no point in having a different id column.
        //
        // we need to store the entire ratchet states for each conversation
        //
        // TODO: might be easier to store all content as bytes blos and deserialize on load,
        //       but that would make queries harder if we want to do anything more complex later on

        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS local_users (
                username TEXT NOT NULL PRIMARY KEY,
                identity_sk BLOB NOT NULL,
                signed_prekey_sk BLOB NOT NULL,
                kem_decap BLOB NOT NULL
            );",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS kem_keys(
                id BLOB PRIMARY KEY,
                username TEXT NOT NULL,
                decap BLOB NOT NULL,
                used INTEGER NOT NULL,
                FOREIGN KEY (username) REFERENCES local_users(username) ON DELETE CASCADE
            );",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ec_keys(
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                sk BLOB NOT NULL,
                used INTEGER NOT NULL,
                FOREIGN KEY (username) REFERENCES local_users(username) ON DELETE CASCADE
            );",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS conversations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                peer TEXT NOT NULL,
                ratchet_state BLOB NOT NULL,
                UNIQUE (username, peer),
                FOREIGN KEY (username) REFERENCES local_users(username) ON DELETE CASCADE
            );",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS messages(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                is_sender INTEGER NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
            );",
        )
        .execute(pool)
        .await?;

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

    let one_time_keys = stored.ec_store.unwrap_or_else(pqxdh::KeyStore::new);
    let one_time_kem_keys = stored.kem_store.unwrap_or_else(pqxdh::KeyStore::new);
    let one_time_prekey_id = one_time_keys
        .iter()
        .map(|(id, _, _)| *id)
        .max()
        .map(|id| id.saturating_add(1))
        .unwrap_or(0);
    let last_resort_id =
        pqxdh::kem_id_from_key(last_resort_kem.encap_key.as_bytes().as_slice());

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

fn ratchet_state_to_bytes(state: &RatchetState) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(209);
    bytes.extend_from_slice(&state.sending_sk.to_bytes());
    bytes.extend_from_slice(state.sending_pk.as_bytes());
    match &state.receiving_pk {
        Some(pk) => {
            bytes.push(1u8);
            bytes.extend_from_slice(pk.as_bytes());
        }
        None => {
            bytes.push(0u8);
            bytes.extend_from_slice(&[0u8; 32]);
        }
    }
    bytes.extend_from_slice(&state.receiving_counter.to_le_bytes());
    bytes.extend_from_slice(&state.sending_counter.to_le_bytes());
    bytes.extend_from_slice(&state.root_key);
    bytes.extend_from_slice(&state.chain_key_sending);
    bytes.extend_from_slice(&state.chain_key_receiving);
    bytes
}

fn ratchet_state_from_bytes(bytes: &[u8]) -> Result<RatchetState> {
    const EXPECTED_LEN: usize = 209;
    if bytes.len() != EXPECTED_LEN {
        return Err(anyhow!("invalid ratchet state length: {}", bytes.len()));
    }

    let mut offset = 0;
    let sending_sk = bytes_to_32(&bytes[offset..offset + 32])?;
    offset += 32;
    let sending_pk = bytes_to_32(&bytes[offset..offset + 32])?;
    offset += 32;
    let has_receiving = bytes[offset];
    offset += 1;
    let receiving_pk_bytes = bytes_to_32(&bytes[offset..offset + 32])?;
    offset += 32;
    let receiving_counter = u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .map_err(|_| anyhow!("invalid receiving counter length"))?,
    );
    offset += 8;
    let sending_counter = u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .map_err(|_| anyhow!("invalid sending counter length"))?,
    );
    offset += 8;
    let root_key = bytes_to_32(&bytes[offset..offset + 32])?;
    offset += 32;
    let chain_key_sending = bytes_to_32(&bytes[offset..offset + 32])?;
    offset += 32;
    let chain_key_receiving = bytes_to_32(&bytes[offset..offset + 32])?;

    let receiving_pk = if has_receiving == 1 {
        Some(x25519::PublicKey::from(receiving_pk_bytes))
    } else {
        None
    };

    Ok(RatchetState {
        sending_sk: x25519::StaticSecret::from(sending_sk),
        sending_pk: x25519::PublicKey::from(sending_pk),
        receiving_pk,
        receiving_counter,
        sending_counter,
        root_key,
        chain_key_sending,
        chain_key_receiving,
    })
}

#[cfg(test)]
#[path = "tests/local_store.rs"]
mod tests;
