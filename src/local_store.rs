use anyhow::{Result, anyhow};
use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::Signer;
use ml_kem::{Encoded, EncodedSizeUser, MlKem1024Params, kem::DecapsulationKey};
use tokio_rusqlite::Connection;
use tokio_rusqlite::Error as TokioRusqliteError;
use tokio_rusqlite::rusqlite::{Error as RusqliteError, OptionalExtension, params};
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
    db: Arc<Connection>,
}

struct StoredUser {
    identity_sk: [u8; 32],
    signed_prekey_sk: [u8; 32],
    kem_decap: Vec<u8>,
    kem_store: Option<KeyStore<KemId, SignedMlKemPrekey>>,
    ec_store: Option<KeyStore<u32, SignedPrekey>>,
}

impl LocalStorage {
    pub async fn new() -> Result<Self> {
        Self::new_with_path("newspeak.db").await
    }

    pub async fn new_with_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let db = Connection::open(path).await?;
        Self::init_migrations(&db).await?;

        Ok(LocalStorage { db: Arc::new(db) })
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
        let db = Arc::clone(&self.db);
        let username_owned = username.to_string();
        let row = db
            .call(move |conn| {
                conn.query_row(
                    "SELECT identity_sk, signed_prekey_sk, kem_decap
                     FROM local_users
                     WHERE username = ?1",
                    params![username_owned],
                    |row| {
                        let identity_sk: Vec<u8> = row.get(0)?;
                        let signed_prekey_sk: Vec<u8> = row.get(1)?;
                        let kem_decap: Vec<u8> = row.get(2)?;
                        Ok((identity_sk, signed_prekey_sk, kem_decap))
                    },
                )
                .optional()
            })
            .await
            .map_err(|err| anyhow!(err))?;

        let Some((identity_sk, signed_prekey_sk, kem_decap)) = row else {
            return Ok(None);
        };

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
        let db = Arc::clone(&self.db);
        let username = username.to_string();
        let row = db
            .call(move |conn| {
                conn.query_row(
                    "SELECT identity_sk
                     FROM local_users
                     WHERE username = ?1",
                    params![username],
                    |row| {
                        let identity_sk: Vec<u8> = row.get(0)?;
                        Ok(identity_sk)
                    },
                )
                .optional()
            })
            .await
            .map_err(|err| anyhow!(err))?;

        let Some(identity_sk) = row else {
            return Ok(None);
        };

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
        let db = Arc::clone(&self.db);
        let username_owned = username.to_string();

        db.call(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO local_users (
                    username,
                    identity_sk,
                    signed_prekey_sk,
                    kem_decap
                ) VALUES (?1, ?2, ?3, ?4)",
                params![username_owned, identity_sk, signed_prekey_sk, kem_decap],
            )?;
            tx.commit()?;
            Ok::<(), RusqliteError>(())
        })
        .await
        .map_err(|err| anyhow!(err))?;

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
        let db = Arc::clone(&self.db);
        let username = username.to_string();

        db.call(move |conn| {
            let tx = conn.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO kem_keys (
                        id,
                        username,
                        decap,
                        used
                    ) VALUES (?1, ?2, ?3, ?4)",
                )?;
                for (id, key_bytes, used) in rows {
                    stmt.execute(params![id, &username, key_bytes, used])?;
                }
            }
            tx.commit()?;
            Ok::<(), RusqliteError>(())
        })
        .await
        .map_err(|err| anyhow!(err))?;

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
        let db = Arc::clone(&self.db);
        let username = username.to_string();

        db.call(move |conn| {
            let tx = conn.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO ec_keys (
                        id,
                        username,
                        sk,
                        used
                    ) VALUES (?1, ?2, ?3, ?4)",
                )?;
                for (id, key_bytes, used) in rows {
                    stmt.execute(params![id, &username, key_bytes, used])?;
                }
            }
            tx.commit()?;
            Ok::<(), RusqliteError>(())
        })
        .await
        .map_err(|err| anyhow!(err))?;

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
        let db = Arc::clone(&self.db);
        let username = username.to_string();
        let rows = db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, decap, used
                    FROM kem_keys
                    WHERE username = ?1",
                )?;
                let rows = stmt.query_map(params![username], |row| {
                    let id: Vec<u8> = row.get(0)?;
                    let decap: Vec<u8> = row.get(1)?;
                    let used: i64 = row.get(2)?;
                    Ok((id, decap, used))
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok::<_, RusqliteError>(results)
            })
            .await
            .map_err(|err| anyhow!(err))?;

        for (id_bytes, decap, used) in rows {
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
        let db = Arc::clone(&self.db);
        let username = username.to_string();
        let rows = db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, sk, used
                    FROM ec_keys
                    WHERE username = ?1",
                )?;
                let rows = stmt.query_map(params![username], |row| {
                    let id: i64 = row.get(0)?;
                    let sk: Vec<u8> = row.get(1)?;
                    let used: i64 = row.get(2)?;
                    Ok((id, sk, used))
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok::<_, RusqliteError>(results)
            })
            .await
            .map_err(|err| anyhow!(err))?;

        for (id, sk, used) in rows {
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
        let db = Arc::clone(&self.db);
        let username = username.to_string();
        let peer = peer.to_string();
        let row = db
            .call(move |conn| {
                conn.query_row(
                    "SELECT ratchet_state
                     FROM conversations
                     WHERE username = ?1 AND peer = ?2",
                    params![username, peer],
                    |row| {
                        let ratchet_state: Vec<u8> = row.get(0)?;
                        Ok(ratchet_state)
                    },
                )
                .optional()
            })
            .await
            .map_err(|err| anyhow!(err))?;

        let Some(ratchet_state) = row else {
            return Ok(None);
        };

        Ok(Some(ratchet_state_from_bytes(&ratchet_state)?))
    }

    pub async fn update_conversation(
        &self,
        username: &str,
        peer: &str,
        ratchet_state: &RatchetState,
    ) -> Result<()> {
        let ratchet_state = ratchet_state_to_bytes(ratchet_state);
        let db = Arc::clone(&self.db);
        let username = username.to_string();
        let peer = peer.to_string();

        db.call(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO conversations (
                    username,
                    peer,
                    ratchet_state
                ) VALUES (?1, ?2, ?3)
                ON CONFLICT(username, peer)
                DO UPDATE SET ratchet_state = excluded.ratchet_state",
                params![username, peer, ratchet_state],
            )?;
            tx.commit()?;
            Ok::<(), RusqliteError>(())
        })
        .await
        .map_err(|err| anyhow!(err))?;

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
        let db = Arc::clone(&self.db);
        let content = content.to_string();
        let is_sender = if is_sender { 1 } else { 0 };

        db.call(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO messages (
                    conversation_id,
                    content,
                    is_sender
                ) VALUES (?1, ?2, ?3)",
                params![conversation_id, content, is_sender],
            )?;
            tx.commit()?;
            Ok::<(), RusqliteError>(())
        })
        .await
        .map_err(|err| anyhow!(err))?;

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
        let db = Arc::clone(&self.db);

        let rows = db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT content, is_sender
                     FROM messages
                     WHERE conversation_id = ?1
                     ORDER BY id ASC",
                )?;
                let rows = stmt.query_map(params![conversation_id], |row| {
                    let content: String = row.get(0)?;
                    let is_sender: i64 = row.get(1)?;
                    Ok((content, is_sender))
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok::<_, RusqliteError>(results)
            })
            .await
            .map_err(|err| anyhow!(err))?;

        let messages = rows
            .into_iter()
            .map(|(content, is_sender)| ConversationMessage {
                content,
                is_sender: is_sender != 0,
            })
            .collect();

        Ok(messages)
    }

    async fn get_conversation_id(&self, username: &str, peer: &str) -> Result<Option<i64>> {
        let db = Arc::clone(&self.db);
        let username = username.to_string();
        let peer = peer.to_string();
        let row = db
            .call(move |conn| {
                conn.query_row(
                    "SELECT id
                     FROM conversations
                     WHERE username = ?1 AND peer = ?2",
                    params![username, peer],
                    |row| row.get(0),
                )
                .optional()
            })
            .await
            .map_err(|err| anyhow!(err))?;

        Ok(row)
    }

    pub async fn get_user_conversations(&self, username: &str) -> Result<Vec<String>> {
        let db = Arc::clone(&self.db);
        let username = username.to_string();
        let rows = db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT peer
                     FROM conversations
                     WHERE username = ?1",
                )?;
                let rows = stmt.query_map(params![username], |row| {
                    let peer: String = row.get(0)?;
                    Ok(peer)
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok::<_, RusqliteError>(results)
            })
            .await
            .map_err(|err| anyhow!(err))?;

        Ok(rows)
    }

    async fn init_migrations(conn: &Connection) -> Result<(), TokioRusqliteError<RusqliteError>> {
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

        conn.call(|conn| {
            conn.execute_batch(
                "PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS local_users (
                    username TEXT NOT NULL PRIMARY KEY,
                    identity_sk BLOB NOT NULL,
                    signed_prekey_sk BLOB NOT NULL,
                    kem_decap BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS kem_keys(
                    id BLOB PRIMARY KEY,
                    username TEXT NOT NULL,
                    decap BLOB NOT NULL,
                    used INTEGER NOT NULL,
                    FOREIGN KEY (username) REFERENCES local_users(username) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS ec_keys(
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL,
                    sk BLOB NOT NULL,
                    used INTEGER NOT NULL,
                    FOREIGN KEY (username) REFERENCES local_users(username) ON DELETE CASCADE
                );",
            )?;

            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS conversations(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        peer TEXT NOT NULL,
                        ratchet_state BLOB NOT NULL,
                        UNIQUE (username, peer),
                        FOREIGN KEY (username) REFERENCES local_users(username) ON DELETE CASCADE
                    );",
            )?;

            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS messages(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    is_sender INTEGER NOT NULL,
                    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
                );",
            )?;

            Ok::<(), RusqliteError>(())
        })
        .await
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

    Ok(pqxdh::KeyExchangeUser {
        identity_sk,
        identity_pk,
        signed_prekey,
        last_resort_kem,
        last_resort_id: rand::random(),
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
mod tests {
    use super::*;
    use std::fs;

    struct TempDb {
        path: std::path::PathBuf,
    }

    impl TempDb {
        fn new() -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("newspeak-test-{}.db", rand::random::<u64>()));
            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[tokio::test]
    async fn local_storage_loads_one_time_keys() -> Result<()> {
        let db = TempDb::new();
        let storage = LocalStorage::new_with_path(&db.path).await?;
        let mut user = pqxdh::KeyExchangeUser::new();
        user.one_time_keys = pqxdh::KeyStore::new();
        user.one_time_kem_keys = pqxdh::KeyStore::new();
        user.one_time_prekey_id = 0;
        storage.insert_user("alice", &user).await?;

        let mut rng = rand::thread_rng();
        let mut identity_sk = user.identity_sk.clone();
        let ec_key_used = pqxdh::SignedPrekey::new(&mut rng, &mut identity_sk);
        let ec_key_unused = pqxdh::SignedPrekey::new(&mut rng, &mut identity_sk);
        let kem_key_used = pqxdh::SignedMlKemPrekey::new(&mut rng, &mut identity_sk);
        let kem_key_unused = pqxdh::SignedMlKemPrekey::new(&mut rng, &mut identity_sk);
        let ec_id_used = 7u32;
        let ec_id_unused = 9u32;
        let kem_id_used: KemId = rand::random();
        let kem_id_unused: KemId = rand::random();

        let mut ec_store = pqxdh::KeyStore::new();
        ec_store.insert(ec_id_used, ec_key_used.clone());
        ec_store.insert(ec_id_unused, ec_key_unused.clone());
        ec_store.mark_used(&ec_id_used);

        let mut kem_store = pqxdh::KeyStore::new();
        kem_store.insert(kem_id_used, kem_key_used.clone());
        kem_store.insert(kem_id_unused, kem_key_unused.clone());
        kem_store.mark_used(&kem_id_used);

        storage.insert_ec_keys("alice", &ec_store).await?;
        storage.insert_kem_keys("alice", &kem_store).await?;

        let ec_keys = storage.get_user_ec_keys("alice").await?;
        let kem_keys = storage.get_user_kem_keys("alice").await?;

        assert_eq!(ec_keys.len(), 2);
        assert_eq!(kem_keys.len(), 2);
        assert_eq!(ec_keys.is_used(&ec_id_used), Some(true));
        assert_eq!(ec_keys.is_used(&ec_id_unused), Some(false));
        assert_eq!(kem_keys.is_used(&kem_id_used), Some(true));
        assert_eq!(kem_keys.is_used(&kem_id_unused), Some(false));

        let ec_loaded = ec_keys.get(&ec_id_used).expect("ec key");
        assert_eq!(
            ec_loaded.public_key.as_bytes(),
            ec_key_used.public_key.as_bytes()
        );
        let ec_loaded = ec_keys.get(&ec_id_unused).expect("ec key");
        assert_eq!(
            ec_loaded.public_key.as_bytes(),
            ec_key_unused.public_key.as_bytes()
        );
        let kem_loaded = kem_keys.get(&kem_id_used).expect("kem key");
        assert_eq!(
            kem_loaded.encap_key.as_bytes(),
            kem_key_used.encap_key.as_bytes()
        );
        let kem_loaded = kem_keys.get(&kem_id_unused).expect("kem key");
        assert_eq!(
            kem_loaded.encap_key.as_bytes(),
            kem_key_unused.encap_key.as_bytes()
        );

        Ok(())
    }

    #[tokio::test]
    async fn load_or_create_user_is_stable() -> Result<()> {
        let db = TempDb::new();
        let storage = LocalStorage::new_with_path(&db.path).await?;

        let first = storage.load_or_create_user("alice").await?;
        let second = storage.load_or_create_user("alice").await?;

        assert_eq!(first.identity_pk.as_bytes(), second.identity_pk.as_bytes());
        assert_eq!(
            first.signed_prekey.public_key.as_bytes(),
            second.signed_prekey.public_key.as_bytes()
        );
        assert_eq!(
            first.last_resort_kem.encap_key.as_bytes(),
            second.last_resort_kem.encap_key.as_bytes()
        );

        Ok(())
    }

    #[tokio::test]
    async fn insert_user_persists_keys() -> Result<()> {
        let db = TempDb::new();
        let storage = LocalStorage::new_with_path(&db.path).await?;

        let mut rng = rand::thread_rng();
        let mut identity_sk = ed25519_dalek::SigningKey::generate(&mut rng);
        let identity_pk = identity_sk.verifying_key();
        let signed_prekey = pqxdh::SignedPrekey::new(&mut rng, &mut identity_sk);
        let last_resort_kem = pqxdh::SignedMlKemPrekey::new(&mut rng, &mut identity_sk);

        let user = pqxdh::KeyExchangeUser {
            identity_sk,
            identity_pk,
            signed_prekey,
            last_resort_kem,
            last_resort_id: rand::random(),
            one_time_keys: pqxdh::KeyStore::new(),
            one_time_kem_keys: pqxdh::KeyStore::new(),
            one_time_prekey_id: 0,
        };

        storage.insert_user("bob", &user).await?;
        let loaded = storage.load_or_create_user("bob").await?;

        assert_eq!(user.identity_pk.as_bytes(), loaded.identity_pk.as_bytes());
        assert_eq!(
            user.signed_prekey.public_key.as_bytes(),
            loaded.signed_prekey.public_key.as_bytes()
        );
        assert_eq!(
            user.last_resort_kem.encap_key.as_bytes(),
            loaded.last_resort_kem.encap_key.as_bytes()
        );

        Ok(())
    }

    #[tokio::test]
    async fn conversation_roundtrip() -> Result<()> {
        let db = TempDb::new();
        let storage = LocalStorage::new_with_path(&db.path).await?;
        storage.load_or_create_user("alice").await?;

        let shared_key: [u8; 32] = rand::random();
        let mut alice = RatchetState::new();
        let bob = RatchetState::new();
        alice.as_initiator(shared_key, bob.sending_pk);
        let _ = alice.send_message("hello", b"ratchet-ad")?;

        storage.update_conversation("alice", "bob", &alice).await?;
        let loaded = storage.get_conversation("alice", "bob").await?;
        let loaded = loaded.expect("conversation");

        assert_eq!(alice.sending_sk.to_bytes(), loaded.sending_sk.to_bytes());
        assert_eq!(alice.sending_pk.as_bytes(), loaded.sending_pk.as_bytes());
        assert_eq!(
            alice.receiving_pk.map(|pk| pk.as_bytes().to_owned()),
            loaded.receiving_pk.map(|pk| pk.as_bytes().to_owned())
        );
        assert_eq!(alice.receiving_counter, loaded.receiving_counter);
        assert_eq!(alice.sending_counter, loaded.sending_counter);
        assert_eq!(alice.root_key, loaded.root_key);
        assert_eq!(alice.chain_key_sending, loaded.chain_key_sending);
        assert_eq!(alice.chain_key_receiving, loaded.chain_key_receiving);

        Ok(())
    }

    #[tokio::test]
    async fn update_conversation_overwrites_state() -> Result<()> {
        let db = TempDb::new();
        let storage = LocalStorage::new_with_path(&db.path).await?;
        storage.load_or_create_user("alice").await?;

        let shared_key: [u8; 32] = rand::random();
        let mut alice = RatchetState::new();
        let bob = RatchetState::new();
        alice.as_initiator(shared_key, bob.sending_pk);
        storage.update_conversation("alice", "bob", &alice).await?;

        let _ = alice.send_message("hello", b"ratchet-ad")?;
        storage.update_conversation("alice", "bob", &alice).await?;
        let loaded = storage
            .get_conversation("alice", "bob")
            .await?
            .expect("conversation");

        assert_eq!(alice.sending_counter, loaded.sending_counter);
        assert_eq!(alice.chain_key_sending, loaded.chain_key_sending);

        Ok(())
    }

    #[tokio::test]
    async fn conversation_messages_roundtrip() -> Result<()> {
        let db = TempDb::new();
        let storage = LocalStorage::new_with_path(&db.path).await?;
        storage.load_or_create_user("alice").await?;

        let shared_key: [u8; 32] = rand::random();
        let mut alice = RatchetState::new();
        let bob = RatchetState::new();
        alice.as_initiator(shared_key, bob.sending_pk);
        storage.update_conversation("alice", "bob", &alice).await?;

        storage.add_message("alice", "bob", "hi bob", true).await?;
        storage
            .add_message("alice", "bob", "hi alice", false)
            .await?;

        let messages = storage.get_conversation_messages("alice", "bob").await?;
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, "hi bob");
        assert!(messages[0].is_sender);
        assert_eq!(messages[1].content, "hi alice");
        assert!(!messages[1].is_sender);

        Ok(())
    }

    #[tokio::test]
    async fn get_user_conversations_lists_peers() -> Result<()> {
        let db = TempDb::new();
        let storage = LocalStorage::new_with_path(&db.path).await?;
        storage.load_or_create_user("alice").await?;

        let shared_key: [u8; 32] = rand::random();
        let mut alice = RatchetState::new();
        let bob = RatchetState::new();
        alice.as_initiator(shared_key, bob.sending_pk);
        storage.update_conversation("alice", "bob", &alice).await?;

        let mut alice2 = RatchetState::new();
        let charlie = RatchetState::new();
        alice2.as_initiator(shared_key, charlie.sending_pk);
        storage
            .update_conversation("alice", "charlie", &alice2)
            .await?;

        let peers = storage.get_user_conversations("alice").await?;
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&"bob".to_string()));
        assert!(peers.contains(&"charlie".to_string()));

        Ok(())
    }
}
