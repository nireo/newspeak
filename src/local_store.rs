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

#[derive(Clone)]
pub struct LocalStorage {
    db: Arc<Connection>,
}

struct StoredUser {
    identity_sk: [u8; 32],
    signed_prekey_sk: [u8; 32],
    kem_decap: Vec<u8>,
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

        self.insert_user(username, &user).await?;
        Ok(user)
    }

    async fn load_user(&self, username: &str) -> Result<Option<StoredUser>> {
        let db = Arc::clone(&self.db);
        let username = username.to_string();
        let row = db
            .call(move |conn| {
                conn.query_row(
                    "SELECT identity_sk, signed_prekey_sk, kem_decap
                     FROM local_users
                     WHERE username = ?1",
                    params![username],
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

        Ok(Some(StoredUser {
            identity_sk: bytes_to_32(&identity_sk)?,
            signed_prekey_sk: bytes_to_32(&signed_prekey_sk)?,
            kem_decap,
        }))
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
        let username = username.to_string();

        db.call(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO local_users (
                    username,
                    identity_sk,
                    signed_prekey_sk,
                    kem_decap
                ) VALUES (?1, ?2, ?3, ?4)",
                params![username, identity_sk, signed_prekey_sk, kem_decap],
            )?;
            tx.commit()?;
            Ok::<(), RusqliteError>(())
        })
        .await
        .map_err(|err| anyhow!(err))?;

        Ok(())
    }

    async fn insert_kem_key(
        &self,
        username: &str,
        id: pqxdh::KemId,
        key: &pqxdh::SignedMlKemPrekey,
    ) -> Result<()> {
        let key_bytes = key.decap_key.as_bytes().as_slice().to_vec();
        let db = Arc::clone(&self.db);
        let username = username.to_string();

        db.call(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO kem_keys (
                    id,
                    username,
                    decap,
                    used
                ) VALUES (?1, ?2, ?3, ?4)",
                params![id, username, key_bytes, 0],
            )?;
            tx.commit()?;
            Ok::<(), RusqliteError>(())
        })
        .await
        .map_err(|err| anyhow!(err))?;

        Ok(())
    }

    async fn insert_ec_key(
        &self,
        username: &str,
        id: u32,
        key: &pqxdh::SignedPrekey,
    ) -> Result<()> {
        let key_bytes = key.private_key.as_bytes().to_vec();
        let db = Arc::clone(&self.db);
        let username = username.to_string();

        db.call(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO ec_keys (
                    id,
                    username,
                    sk,
                    used
                ) VALUES (?1, ?2, ?3, ?4)",
                params![id, username, key_bytes, 0],
            )?;
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
        let Some(stored) = self.load_user(username).await? else {
            return Ok(key_store);
        };
        let identity_sk = ed25519_dalek::SigningKey::from_bytes(&stored.identity_sk);
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
        let Some(stored) = self.load_user(username).await? else {
            return Ok(key_store);
        };
        let identity_sk = ed25519_dalek::SigningKey::from_bytes(&stored.identity_sk);
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

    async fn init_migrations(conn: &Connection) -> Result<(), TokioRusqliteError<RusqliteError>> {
        // some thoughts on the schema: for a relational format it makes more sense to store the
        // user like this, overall sqlite is very reliable and a good also for internal storage in
        // my opinion.
        //
        // also having a blob as the kem key id seems quite weird, but it makes sense since they're
        // internally stored that way and there is no point in having a different id column.

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

    Ok(pqxdh::KeyExchangeUser {
        identity_sk,
        identity_pk,
        signed_prekey,
        last_resort_kem,
        last_resort_id: rand::random(),
        one_time_keys: pqxdh::KeyStore::new(),
        one_time_kem_keys: pqxdh::KeyStore::new(),
        one_time_prekey_id: 0,
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
        let user = storage.load_or_create_user("alice").await?;

        let mut rng = rand::thread_rng();
        let mut identity_sk = user.identity_sk.clone();
        let ec_key = pqxdh::SignedPrekey::new(&mut rng, &mut identity_sk);
        let kem_key = pqxdh::SignedMlKemPrekey::new(&mut rng, &mut identity_sk);
        let ec_id = 7u32;
        let kem_id: KemId = rand::random();

        storage.insert_ec_key("alice", ec_id, &ec_key).await?;
        storage.insert_kem_key("alice", kem_id, &kem_key).await?;

        let db = Arc::clone(&storage.db);
        let kem_id_bytes = kem_id.to_vec();
        db.call(move |conn| {
            conn.execute("UPDATE ec_keys SET used = 1 WHERE id = ?1", params![ec_id])?;
            conn.execute(
                "UPDATE kem_keys SET used = 1 WHERE id = ?1",
                params![kem_id_bytes],
            )?;
            Ok::<(), RusqliteError>(())
        })
        .await
        .map_err(|err| anyhow!(err))?;

        let ec_keys = storage.get_user_ec_keys("alice").await?;
        let kem_keys = storage.get_user_kem_keys("alice").await?;

        assert_eq!(ec_keys.len(), 1);
        assert_eq!(kem_keys.len(), 1);
        assert_eq!(ec_keys.is_used(&ec_id), Some(true));
        assert_eq!(kem_keys.is_used(&kem_id), Some(true));

        let ec_loaded = ec_keys.get(&ec_id).expect("ec key");
        assert_eq!(
            ec_loaded.public_key.as_bytes(),
            ec_key.public_key.as_bytes()
        );
        let kem_loaded = kem_keys.get(&kem_id).expect("kem key");
        assert_eq!(
            kem_loaded.encap_key.as_bytes(),
            kem_key.encap_key.as_bytes()
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
}
