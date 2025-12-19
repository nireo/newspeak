use anyhow::{Context, Error};
use ed25519_dalek::{self as ed25519, ed25519::signature::SignerMut};
use ml_kem::{
    EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update},
};
use x25519_dalek as x25519;

struct KeyExchangeUser {
    identity_sk: ed25519::SigningKey,
    identity_pk: ed25519::VerifyingKey,

    signed_prekey_sk: x25519::ReusableSecret,
    signed_prekey: SignedX25519Prekey,

    last_resort_decap: DecapsulationKey<MlKem1024Params>,
    last_resort_pk: SignedMlKemPrekey,
}

struct SignedX25519Prekey {
    public_key: x25519::PublicKey,
    signature: ed25519::Signature,
}

struct SignedMlKemPrekey {
    encap_key: EncapsulationKey<MlKem1024Params>,
    signature: ed25519::Signature,
}

struct PQXDHInitOutput {
    secret_key: [u8; 32],
    message: PQXDHInitMessage,
}

struct PQXDHInitMessage {
    peer_identity_public_key: ed25519::VerifyingKey,
    ephemeral_x25519_public_key: x25519::PublicKey,
    mlkem_ciphertext: Vec<u8>,
}

struct PrekeyBundle {
    signed_prekey: SignedX25519Prekey,
    kem_prekey: SignedMlKemPrekey,
    identity_pk: ed25519::VerifyingKey,
}

impl KeyExchangeUser {
    fn new() -> KeyExchangeUser {
        let mut rng = rand::thread_rng();

        let mut identity_private_key = ed25519::SigningKey::generate(&mut rng);
        let identity_public_key = identity_private_key.verifying_key();

        let x25519_private_key = x25519::ReusableSecret::random_from_rng(&mut rng);
        let x25519_public_prekey = x25519::PublicKey::from(&x25519_private_key);
        let x25519_public_prekey_signature =
            identity_private_key.sign(x25519_public_prekey.as_bytes());
        let x25519_prekey = SignedX25519Prekey {
            public_key: x25519_public_prekey,
            signature: x25519_public_prekey_signature,
        };

        let (mlkem1024_decap_key, mlkem1024_encap_key) = MlKem1024::generate(&mut rng);
        let mlkem1024_encap_key_signautre =
            identity_private_key.sign(&mlkem1024_encap_key.as_bytes());
        let mlkem1024_prekey = SignedMlKemPrekey {
            encap_key: mlkem1024_encap_key,
            signature: mlkem1024_encap_key_signautre,
        };

        return KeyExchangeUser {
            identity_sk: identity_private_key,
            identity_pk: identity_public_key,
            signed_prekey_sk: x25519_private_key,
            signed_prekey: x25519_prekey,
            last_resort_decap: mlkem1024_decap_key,
            last_resort_pk: mlkem1024_prekey,
        };
    }

    fn init_key_exchange(&self, other: &PrekeyBundle) -> Result<PQXDHInitOutput, Error> {
        let mut rng = rand::thread_rng();

        other
            .identity_pk
            .verify_strict(
                other.signed_prekey.public_key.as_bytes(),
                &other.signed_prekey.signature,
            )
            .with_context(|| "failed to verify X25519 prekey")?;
        other
            .identity_pk
            .verify_strict(
                &other.kem_prekey.encap_key.as_bytes(),
                &other.kem_prekey.signature,
            )
            .with_context(|| "failed to verify ML-KEM-1024 prekey")?;

        // we cannot use the x25519::EmphemeralSecret since we need to use the key multiple times.
        // however since we create the key here and don't store it, it's guaranteed to only be used
        // inside here.
        let ephemeral_sk = x25519::ReusableSecret::random_from_rng(&mut rng);

        let (mlkem_ciphertext, mlkem_shared_secret) = other
            .kem_prekey
            .encap_key
            .encapsulate(&mut rng)
            .map_err(|_| Error::msg("failed to encapsulate with ML-KEM-1024"))?;

        let self_identity_ecdh = ed25519_sk_to_x25519(&self.identity_sk);
        let other_identity_ecdh = ed25519_pk_to_x25519(&other.identity_pk);

        // DH1 = DH(IKA, SPKB)
        let dh_1 = self_identity_ecdh.diffie_hellman(&other.signed_prekey.public_key);
        // DH2 = DH(EKA, IKB)
        let dh_2 = ephemeral_sk.diffie_hellman(&other_identity_ecdh);
        // DH3 = DH(EKA, SPKB)
        let dh_3 = ephemeral_sk.diffie_hellman(&other.signed_prekey.public_key);

        // SK = KDF(DH1 || DH2 || DH3 || SS)
        let secret_key = kdf(
            dh_1.as_bytes(),
            dh_2.as_bytes(),
            dh_3.as_bytes(),
            &mlkem_shared_secret,
        );

        // if a one-time prekey was available, do this instead
        // DH4 = DH(EKA, OPKB)
        // SK = KDF(DH1 || DH2 || DH3 || DH4 || SS)

        let init_message = PQXDHInitMessage {
            peer_identity_public_key: self.identity_pk,
            ephemeral_x25519_public_key: x25519::PublicKey::from(&ephemeral_sk),
            mlkem_ciphertext: mlkem_ciphertext.to_vec(),
        };
        return Ok(PQXDHInitOutput {
            secret_key,
            message: init_message,
        });
    }

    fn receive_key_exchange(
        self: &KeyExchangeUser,
        message: &PQXDHInitMessage,
    ) -> Result<[u8; 32], Error> {
        let mlkem_shared_secret = self
            .last_resort_decap
            .decapsulate(message.mlkem_ciphertext.as_slice().try_into().unwrap())
            .map_err(|_| Error::msg("failed to decapsulate with ML-KEM-1024"))?;

        let alice_identity_public_key_x25519 =
            ed25519_pk_to_x25519(&message.peer_identity_public_key);
        let bob_identity_secret_key_x25519 = ed25519_sk_to_x25519(&self.identity_sk);

        // DH1 = DH(IKA, SPKB)
        let dh_1 = self
            .signed_prekey_sk
            .diffie_hellman(&alice_identity_public_key_x25519);
        // DH2 = DH(EKA, IKB)
        let dh_2 =
            bob_identity_secret_key_x25519.diffie_hellman(&message.ephemeral_x25519_public_key);
        // DH3 = DH(EKA, SPKB)
        let dh_3 = self
            .signed_prekey_sk
            .diffie_hellman(&message.ephemeral_x25519_public_key);

        // SK = KDF(DH1 || DH2 || DH3 || SS)
        let secret_key = kdf(
            dh_1.as_bytes(),
            dh_2.as_bytes(),
            dh_3.as_bytes(),
            &mlkem_shared_secret,
        );

        // TODO: one time prekey
        return Ok(secret_key);
    }

    fn make_prekey(&self) -> PrekeyBundle {
        PrekeyBundle {
            signed_prekey: SignedX25519Prekey {
                public_key: self.signed_prekey.public_key,
                signature: self.signed_prekey.signature,
            },
            kem_prekey: SignedMlKemPrekey {
                encap_key: self.last_resort_pk.encap_key.clone(),
                signature: self.last_resort_pk.signature,
            },
            identity_pk: self.identity_pk,
        }
    }
}

fn kdf(dh1: &[u8], dh2: &[u8], dh3: &[u8], mlkem_shared_secret: &[u8]) -> [u8; 32] {
    static KDF_INFO: &[u8] = b"PQXDH_CURVE25519_SHAKE256_ML-KEM-1024";
    let mut secret_key = [0u8; 32];
    let mut kdf = Shake256::default();
    kdf.update(&[0xffu8; 32]);
    kdf.update(dh1);
    kdf.update(dh2);
    kdf.update(dh3);
    kdf.update(mlkem_shared_secret);
    kdf.update(KDF_INFO);
    kdf.finalize_xof_into(&mut secret_key);
    return secret_key;
}

fn ed25519_sk_to_x25519(ed25519_secret_key: &ed25519::SigningKey) -> x25519::StaticSecret {
    return x25519::StaticSecret::from(ed25519_secret_key.to_scalar_bytes());
}

fn ed25519_pk_to_x25519(ed25519_public_key: &ed25519::VerifyingKey) -> x25519::PublicKey {
    // u = (1 + y) / (1 - y) = (Z + Y) / (Z - Y)
    return x25519::PublicKey::from(ed25519_public_key.to_montgomery().to_bytes());
}

#[cfg(test)]
mod tests {
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
}
