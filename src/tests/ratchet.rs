use super::*;

#[test]
fn ratchet_allows_initiator_to_send_and_receiver_to_decrypt() {
    let shared_key: [u8; 32] = rand::random();
    let mut alice = RatchetState::new();
    let mut bob = RatchetState::new();

    let bob_pk = ecdh::PublicKey::from(&bob.sending_sk);
    alice.as_initiator(shared_key, bob_pk);
    bob.as_receiver(shared_key);

    let ad = b"header-data";
    let message = alice.send_message("hello", ad).unwrap();

    assert_eq!(alice.sending_counter, 1);
    assert_eq!(bob.receiving_counter, 0);

    bob.receive_message(message, ad).unwrap();

    assert_eq!(bob.receiving_counter, 1);
    assert_eq!(bob.receiving_pk, Some(alice.sending_pk));
}

#[test]
fn ratchet_allows_bidirectional_messages() {
    let shared_key: [u8; 32] = rand::random();
    let mut alice = RatchetState::new();
    let mut bob = RatchetState::new();

    let bob_initial_pk = ecdh::PublicKey::from(&bob.sending_sk);
    alice.as_initiator(shared_key, bob_initial_pk);
    bob.as_receiver(shared_key);

    let ad = b"ratchet-ad";
    let to_bob = alice.send_message("ping", ad).unwrap();
    bob.receive_message(to_bob, ad).unwrap();

    let bob_reply_pk = ecdh::PublicKey::from(&bob.sending_sk);
    let to_alice = bob.send_message("pong", ad).unwrap();
    alice.receive_message(to_alice, ad).unwrap();

    assert_eq!(alice.receiving_pk, Some(bob_reply_pk));
    assert_eq!(alice.receiving_counter, 1);
    assert_eq!(bob.sending_counter, 1);
    assert_eq!(bob.receiving_counter, 1);
}

#[test]
#[should_panic]
fn ratchet_rejects_message_with_wrong_additional_data() {
    let shared_key: [u8; 32] = rand::random();
    let mut alice = RatchetState::new();
    let mut bob = RatchetState::new();

    let bob_pk = ecdh::PublicKey::from(&bob.sending_sk);
    alice.as_initiator(shared_key, bob_pk);
    bob.as_receiver(shared_key);

    let message = alice.send_message("secret", b"correct-ad").unwrap();
    bob.receive_message(message, b"incorrect-ad").unwrap();
}

#[test]
fn ratchet_rejects_message_with_tampered_counter() {
    let shared_key: [u8; 32] = rand::random();
    let mut alice = RatchetState::new();
    let mut bob = RatchetState::new();

    let bob_pk = ecdh::PublicKey::from(&bob.sending_sk);
    alice.as_initiator(shared_key, bob_pk);
    bob.as_receiver(shared_key);

    let ad = b"ratchet-ad";
    let mut message = alice.send_message("secret", ad).unwrap();
    message.header.counter += 1;
    assert!(bob.receive_message(message, ad).is_err());
}
