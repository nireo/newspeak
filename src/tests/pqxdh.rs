use super::SignerMut;
use super::*;

#[test]
fn pqxdh_round_trip_shared_secret_matches() {
    let alice = KeyExchangeUser::new();
    let bob = KeyExchangeUser::new();
    let bob_bundle = bob.make_prekey();

    let init = alice.init_key_exchange(&bob_bundle).expect("init");
    let received = bob.receive_key_exchange(&init.message).expect("receive");

    assert_eq!(init.secret_key, received);
}

#[test]
fn pqxdh_uses_one_time_kem_key_when_available() {
    let alice = KeyExchangeUser::new();
    let bob = KeyExchangeUser::new();
    let bob_bundle = bob.make_prekey();

    assert!(bob.one_time_kem_keys.get(&bob_bundle.kem_id).is_some());
    assert_ne!(
        bob_bundle.kem_prekey.encap_key.as_bytes(),
        bob.last_resort_kem.encap_key.as_bytes()
    );

    let init = alice.init_key_exchange(&bob_bundle).expect("init");
    let received = bob.receive_key_exchange(&init.message).expect("receive");

    assert_eq!(init.secret_key, received);
}

#[test]
fn pqxdh_rejects_invalid_x25519_prekey_signature() {
    let alice = KeyExchangeUser::new();
    let bob = KeyExchangeUser::new();
    let mut bob_bundle = bob.make_prekey();

    let mut rng = rand::thread_rng();
    let mut fake_signer = ed25519::SigningKey::generate(&mut rng);
    bob_bundle.signed_prekey.signature =
        fake_signer.sign(bob_bundle.signed_prekey.public_key.as_bytes());

    assert!(alice.init_key_exchange(&bob_bundle).is_err());
}

#[test]
fn pqxdh_rejects_invalid_ml_kem_prekey_signature() {
    let alice = KeyExchangeUser::new();
    let bob = KeyExchangeUser::new();
    let mut bob_bundle = bob.make_prekey();

    let mut rng = rand::thread_rng();
    let mut fake_signer = ed25519::SigningKey::generate(&mut rng);
    bob_bundle.kem_prekey.signature =
        fake_signer.sign(&bob_bundle.kem_prekey.encap_key.as_bytes());

    assert!(alice.init_key_exchange(&bob_bundle).is_err());
}
