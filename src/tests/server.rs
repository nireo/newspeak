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

fn sample_prekey_with_id(kind: KeyKind, key: &[u8], signature: &[u8], id: u32) -> SignedPrekey {
    SignedPrekey {
        kind: kind as i32,
        key: key.to_vec(),
        signature: signature.to_vec(),
        id,
    }
}

async fn test_service() -> NewspeakService {
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_db(&db).await.unwrap();
    NewspeakService {
        users: Arc::new(DashMap::new()),
        server_store: ServerStore::new(db),
        auth_challenges: Arc::new(AsyncMutex::new(HashMap::new())),
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
async fn register_is_idempotent_for_existing_username() {
    let svc = test_service().await;
    let request = RegisterRequest {
        username: "bob".to_string(),
        identity_key: vec![11, 12],
        signed_prekey: Some(sample_prekey(KeyKind::X25519, &[13], &[14])),
        one_time_prekeys: vec![],
        kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[15], &[16])),
    };

    svc.register(Request::new(request.clone())).await.unwrap();
    let response = svc.register(Request::new(request)).await.unwrap();
    assert_eq!(response.into_inner().auth_challenge.len(), 32);
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
        one_time_prekeys: vec![sample_prekey_with_id(KeyKind::X25519, &[23], &[24], bob_id)],
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
async fn add_one_time_prekeys_ignores_duplicates() {
    let svc = test_service().await;
    let request = RegisterRequest {
        username: "dana".to_string(),
        identity_key: vec![1],
        signed_prekey: Some(sample_prekey(KeyKind::X25519, &[2], &[3])),
        one_time_prekeys: vec![sample_prekey_with_id(KeyKind::X25519, &[4], &[5], 1)],
        kem_prekey: Some(sample_prekey(KeyKind::MlKem1024, &[6], &[7])),
    };

    svc.register(Request::new(request)).await.unwrap();
    let user = svc
        .server_store
        .get_user("dana".to_string())
        .await
        .unwrap();
    let user_id = user.id.unwrap();

    let prekeys = vec![
        StoredPrekey {
            id: 1,
            prekey: sample_prekey_with_id(KeyKind::X25519, &[8], &[9], 1),
        },
        StoredPrekey {
            id: 2,
            prekey: sample_prekey_with_id(KeyKind::X25519, &[10], &[11], 2),
        },
    ];

    let count = svc
        .server_store
        .add_one_time_prekeys(user_id, prekeys, vec![])
        .await
        .unwrap();
    assert_eq!(count, 1);

    let counts = svc.server_store.count_one_time_keys().await.unwrap();
    assert_eq!(counts, (2, 0));
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
