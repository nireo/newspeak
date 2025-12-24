use anyhow::{Result, anyhow};
use std::sync::Arc;

use ed25519_dalek::Signer;
use ml_kem::{Encoded, EncodedSizeUser, MlKem1024Params, kem::DecapsulationKey};
use tokio_rusqlite::Connection;
use tokio_rusqlite::Error as TokioRusqliteError;
use tokio_rusqlite::rusqlite::{Error as RusqliteError, OptionalExtension, params};
use x25519_dalek as x25519;

use crate::pqxdh;

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
        let db = Connection::open("newspeak.db").await?;
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
        let kem_decap = user.last_resort_kem.decap_key.as_bytes().to_vec();
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

    async fn init_migrations(conn: &Connection) -> Result<(), TokioRusqliteError<RusqliteError>> {
        conn.call(|conn| {
            conn.execute_batch(
                "PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS local_users (
                    username TEXT NOT NULL PRIMARY KEY,
                    identity_sk BLOB NOT NULL,
                    signed_prekey_sk BLOB NOT NULL,
                    kem_decap BLOB NOT NULL
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
