use std::{collections::HashMap, hash::Hash};

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
use x25519_dalek::{self as x25519, SharedSecret};

type KemId = [u8; 16];

pub struct KeyExchangeUser {
    pub identity_sk: ed25519::SigningKey,
    pub identity_pk: ed25519::VerifyingKey,
    pub signed_prekey: SignedPrekey,

    pub last_resort_decap: DecapsulationKey<MlKem1024Params>,
    pub last_resort_pk: SignedMlKemPrekey,
    pub last_resort_id: KemId,

    pub one_time_keys: KeyStore<u32, SignedPrekey>,
    pub one_time_kem_keys: KeyStore<KemId, SignedMlKemPrekey>,
}

pub struct OneTimeKey<T> {
    key: T,
    used: bool,
}

pub struct KeyStore<I: Hash + Eq, T> {
    store: HashMap<I, OneTimeKey<T>>,
}

impl<I: Hash + Eq, T> KeyStore<I, T> {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    pub fn get_id(&self, id: &I) -> Option<&OneTimeKey<T>> {
        self.store.get(id)
    }

    pub fn mark_used(&mut self, id: &I) {
        if let Some(val) = self.store.get_mut(&id) {
            val.used = true;
        }
    }
}

pub struct SignedPrekey {
    pub private_key: x25519::ReusableSecret,
    pub public_key: x25519::PublicKey,
    pub signature: ed25519::Signature,
}

pub struct SignedMlKemPrekey {
    pub encap_key: EncapsulationKey<MlKem1024Params>,
    pub signature: ed25519::Signature,
}

pub struct PQXDHInitOutput {
    secret_key: [u8; 32],

    // The message here is public information as is to be shared.
    message: PQXDHInitMessage,
}

pub struct PQXDHInitMessage {
    peer_identity_public_key: ed25519::VerifyingKey,
    ephemeral_x25519_public_key: x25519::PublicKey,
    mlkem_ciphertext: Vec<u8>,
    kem_used: KemId,
    one_time_prekey_used: Option<u32>,
}

pub struct PrekeyBundle {
    signed_prekey: SignedPrekey,
    kem_prekey: SignedMlKemPrekey,
    identity_pk: ed25519::VerifyingKey,
    one_time_prekey: Option<SignedPrekey>,
    one_time_prekey_id: Option<u32>,
    kem_id: KemId,
}

fn generate_kem_id() -> [u8; 16] {
    rand::random()
}

impl KeyExchangeUser {
    pub fn new() -> KeyExchangeUser {
        let mut rng = rand::thread_rng();

        let mut identity_private_key = ed25519::SigningKey::generate(&mut rng);
        let identity_public_key = identity_private_key.verifying_key();

        let signed_prekey_sk = x25519::ReusableSecret::random_from_rng(&mut rng);
        let signed_prekey_pk = x25519::PublicKey::from(&signed_prekey_sk);
        let signed_prekey_sig = identity_private_key.sign(signed_prekey_pk.as_bytes());
        let signed_prekey = SignedPrekey {
            private_key: signed_prekey_sk,
            public_key: signed_prekey_pk,
            signature: signed_prekey_sig,
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
            signed_prekey,
            last_resort_decap: mlkem1024_decap_key,
            last_resort_pk: mlkem1024_prekey,
            last_resort_id: generate_kem_id(),
            one_time_keys: KeyStore::new(),
            one_time_kem_keys: KeyStore::new(),
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

        let mut dh_4: Option<[u8; 32]> = None;
        if let Some(otpk) = other.one_time_prekey.as_ref() {
            other
                .identity_pk
                .verify_strict(otpk.public_key.as_bytes(), &otpk.signature)
                .with_context(|| "failed to verify one-time prekey")?;
            dh_4 = Some(ephemeral_sk.diffie_hellman(&otpk.public_key).to_bytes());
        }

        let secret_key = kdf(
            dh_1.as_bytes(),
            dh_2.as_bytes(),
            dh_3.as_bytes(),
            dh_4.as_ref(),
            &mlkem_shared_secret,
        );

        // if a one-time prekey was available, do this instead
        // DH4 = DH(EKA, OPKB)
        // SK = KDF(DH1 || DH2 || DH3 || DH4 || SS)

        let init_message = PQXDHInitMessage {
            peer_identity_public_key: self.identity_pk,
            ephemeral_x25519_public_key: x25519::PublicKey::from(&ephemeral_sk),
            mlkem_ciphertext: mlkem_ciphertext.as_slice().to_vec(),
            kem_used: other.kem_id,
            one_time_prekey_used: other.one_time_prekey_id,
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
            .signed_prekey
            .private_key
            .diffie_hellman(&alice_identity_public_key_x25519);
        // DH2 = DH(EKA, IKB)
        let dh_2 =
            bob_identity_secret_key_x25519.diffie_hellman(&message.ephemeral_x25519_public_key);
        // DH3 = DH(EKA, SPKB)
        let dh_3 = self
            .signed_prekey
            .private_key
            .diffie_hellman(&message.ephemeral_x25519_public_key);

        let mut dh_4: Option<[u8; 32]> = None;
        if let Some(otpk_id) = message.one_time_prekey_used {
            match self.one_time_keys.get_id(&otpk_id) {
                Some(skey) => {
                    dh_4 = Some(
                        skey.key
                            .private_key
                            .diffie_hellman(&message.ephemeral_x25519_public_key)
                            .to_bytes(),
                    )
                }
                None => {
                    return Err(Error::msg(
                        "cannot create shared secret due to missing one-time-key used.",
                    ));
                }
            }
        }

        // SK = KDF(DH1 || DH2 || DH3 || SS)
        let secret_key = kdf(
            dh_1.as_bytes(),
            dh_2.as_bytes(),
            dh_3.as_bytes(),
            dh_4.as_ref(),
            &mlkem_shared_secret,
        );

        return Ok(secret_key);
    }

    fn make_prekey(&self) -> PrekeyBundle {
        PrekeyBundle {
            signed_prekey: SignedPrekey {
                private_key: self.signed_prekey.private_key.clone(),
                public_key: self.signed_prekey.public_key,
                signature: self.signed_prekey.signature,
            },
            kem_prekey: SignedMlKemPrekey {
                encap_key: self.last_resort_pk.encap_key.clone(),
                signature: self.last_resort_pk.signature,
            },
            identity_pk: self.identity_pk,
            one_time_prekey: None,
            one_time_prekey_id: None,
            kem_id: self.last_resort_id,
        }
    }
}

fn kdf(
    dh1: &[u8],
    dh2: &[u8],
    dh3: &[u8],
    dh4: Option<&[u8; 32]>,
    mlkem_shared_secret: &[u8],
) -> [u8; 32] {
    static KDF_INFO: &[u8] = b"PQXDH_CURVE25519_SHAKE256_ML-KEM-1024";
    let mut secret_key = [0u8; 32];
    let mut kdf = Shake256::default();
    kdf.update(&[0xffu8; 32]);
    kdf.update(dh1);
    kdf.update(dh2);
    kdf.update(dh3);
    if let Some(e) = dh4 {
        kdf.update(e);
    }
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
