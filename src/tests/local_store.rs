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

    let last_resort_id =
        pqxdh::kem_id_from_key(last_resort_kem.encap_key.as_bytes().as_slice());
    let user = pqxdh::KeyExchangeUser {
        identity_sk,
        identity_pk,
        signed_prekey,
        last_resort_kem,
        last_resort_id,
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

    storage
        .add_message("alice", "bob", "hi bob", true, 100)
        .await?;
    storage
        .add_message("alice", "bob", "hi alice", false, 200)
        .await?;

    let messages = storage.get_conversation_messages("alice", "bob").await?;
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].content, "hi bob");
    assert!(messages[0].is_sender);
    assert_eq!(messages[0].timestamp, 100);
    assert_eq!(messages[1].content, "hi alice");
    assert!(!messages[1].is_sender);
    assert_eq!(messages[1].timestamp, 200);

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
