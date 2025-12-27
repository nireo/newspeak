use std::{collections::HashMap, hash::Hash};

use anyhow::{Context, Error};
use ed25519_dalek::{self as ed25519, ed25519::signature::SignerMut};
use ml_kem::{
    EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
};
use rand::{CryptoRng, Rng};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update},
};
use x25519_dalek::{self as x25519};

pub type KemId = [u8; 16];

pub struct KeyExchangeUser {
    pub identity_sk: ed25519::SigningKey,
    pub identity_pk: ed25519::VerifyingKey,
    pub signed_prekey: SignedPrekey,

    pub last_resort_kem: SignedMlKemPrekey,
    pub last_resort_id: KemId,

    pub one_time_keys: KeyStore<u32, SignedPrekey>,
    pub one_time_kem_keys: KeyStore<KemId, SignedMlKemPrekey>,

    pub one_time_prekey_id: u32,
}

#[derive(Clone)]
pub struct OneTimeKey<T: Clone> {
    key: T,
    used: bool,
}

pub struct KeyStore<I: Hash + Eq, T: Clone> {
    store: HashMap<I, OneTimeKey<T>>,
}

impl<I: Hash + Eq, T: Clone> KeyStore<I, T> {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    pub fn get(&self, id: &I) -> Option<&T> {
        self.store.get(id).map(|entry| &entry.key)
    }

    pub fn is_used(&self, id: &I) -> Option<bool> {
        self.store.get(id).map(|entry| entry.used)
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn get_id(&self, id: &I) -> Option<&OneTimeKey<T>> {
        self.store.get(id)
    }

    pub fn mark_used(&mut self, id: &I) {
        if let Some(val) = self.store.get_mut(&id) {
            val.used = true;
        }
    }

    pub fn insert(&mut self, id: I, key: T) {
        self.store.insert(
            id,
            OneTimeKey {
                key: key,
                used: false,
            },
        );
    }

    pub fn insert_with_used(&mut self, id: I, key: T, used: bool) {
        self.store.insert(
            id,
            OneTimeKey {
                key: key,
                used: used,
            },
        );
    }

    pub fn first_unused(&self) -> Option<(&I, &OneTimeKey<T>)> {
        self.store.iter().find(|k| !k.1.used)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&I, &T, bool)> {
        self.store
            .iter()
            .map(|(id, entry)| (id, &entry.key, entry.used))
    }
}

#[derive(Clone)]
pub struct SignedPrekey {
    pub private_key: x25519::StaticSecret,
    pub public_key: x25519::PublicKey,
    pub signature: ed25519::Signature,
}

#[derive(Clone)]
pub struct PublicSignedPrekey {
    pub public_key: x25519::PublicKey,
    pub signature: ed25519::Signature,
}

impl From<&SignedPrekey> for PublicSignedPrekey {
    fn from(k: &SignedPrekey) -> Self {
        PublicSignedPrekey {
            public_key: k.public_key,
            signature: k.signature,
        }
    }
}

impl SignedPrekey {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R, identity_sk: &mut ed25519::SigningKey) -> Self {
        let private_key = x25519::StaticSecret::random_from_rng(rng);
        let public_key = x25519::PublicKey::from(&private_key);
        let signature = identity_sk.sign(public_key.as_bytes());

        SignedPrekey {
            private_key,
            public_key,
            signature,
        }
    }
}

#[derive(Clone)]
pub struct SignedMlKemPrekey {
    pub decap_key: DecapsulationKey<MlKem1024Params>,
    pub encap_key: EncapsulationKey<MlKem1024Params>,
    pub signature: ed25519::Signature,
}

#[derive(Clone)]
pub struct PublicSignedMlKemPrekey {
    pub encap_key: EncapsulationKey<MlKem1024Params>,
    pub signature: ed25519::Signature,
}

impl From<&SignedMlKemPrekey> for PublicSignedMlKemPrekey {
    fn from(k: &SignedMlKemPrekey) -> Self {
        PublicSignedMlKemPrekey {
            encap_key: k.encap_key.clone(),
            signature: k.signature,
        }
    }
}

impl SignedMlKemPrekey {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R, identity_sk: &mut ed25519::SigningKey) -> Self {
        let (mlkem1024_decap_key, mlkem1024_encap_key) = MlKem1024::generate(rng);
        let mlkem1024_encap_key_signautre = identity_sk.sign(&mlkem1024_encap_key.as_bytes());

        SignedMlKemPrekey {
            encap_key: mlkem1024_encap_key,
            decap_key: mlkem1024_decap_key,
            signature: mlkem1024_encap_key_signautre,
        }
    }
}

pub struct PQXDHInitOutput {
    pub secret_key: [u8; 32],

    // The message here is public information as is to be shared.
    pub message: PQXDHInitMessage,
}

pub struct PQXDHInitMessage {
    pub peer_identity_public_key: ed25519::VerifyingKey,
    pub ephemeral_x25519_public_key: x25519::PublicKey,
    pub mlkem_ciphertext: Vec<u8>,
    pub kem_used: KemId,
    pub one_time_prekey_used: Option<u32>,
}

pub struct PrekeyBundle {
    pub signed_prekey: PublicSignedPrekey,
    pub kem_prekey: PublicSignedMlKemPrekey,
    pub identity_pk: ed25519::VerifyingKey,
    pub one_time_prekey: Option<PublicSignedPrekey>,
    pub one_time_prekey_id: Option<u32>,
    pub kem_id: KemId,
}

fn generate_kem_id() -> [u8; 16] {
    rand::random()
}

impl KeyExchangeUser {
    pub fn new() -> KeyExchangeUser {
        let mut rng = rand::thread_rng();

        let mut identity_private_key = ed25519::SigningKey::generate(&mut rng);
        let identity_public_key = identity_private_key.verifying_key();
        let signed_prekey = SignedPrekey::new(&mut rng, &mut identity_private_key);
        let last_resort_kem = SignedMlKemPrekey::new(&mut rng, &mut identity_private_key);

        let mut u = KeyExchangeUser {
            identity_sk: identity_private_key,
            identity_pk: identity_public_key,
            signed_prekey,
            last_resort_kem,
            last_resort_id: generate_kem_id(),
            one_time_keys: KeyStore::new(),
            one_time_kem_keys: KeyStore::new(),
            one_time_prekey_id: 0,
        };

        u.add_one_time_prekeys(10);
        u.add_one_time_kem_keys(10);

        u
    }

    fn add_one_time_prekeys(&mut self, count: usize) {
        let mut rng = rand::thread_rng();
        for _ in 0..count {
            let signed_prekey = SignedPrekey::new(&mut rng, &mut self.identity_sk);
            self.one_time_keys
                .insert(self.one_time_prekey_id, signed_prekey);
            self.one_time_prekey_id += 1;
        }
    }

    fn add_one_time_kem_keys(&mut self, count: usize) {
        let mut rng = rand::thread_rng(); // Init once
        for _ in 0..count {
            let id: KemId = generate_kem_id();
            let signed_prekey = SignedMlKemPrekey::new(&mut rng, &mut self.identity_sk);

            self.one_time_kem_keys.insert(id, signed_prekey);
        }
    }

    pub fn init_key_exchange(&self, other: &PrekeyBundle) -> Result<PQXDHInitOutput, Error> {
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

    pub fn receive_key_exchange(
        self: &KeyExchangeUser,
        message: &PQXDHInitMessage,
    ) -> Result<[u8; 32], Error> {
        let mlkem_shared_secret = self
            .last_resort_kem
            .decap_key
            .decapsulate(message.mlkem_ciphertext.as_slice().try_into()?)
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
        let one_time_prekey = self.one_time_keys.first_unused();
        let mut bundle = PrekeyBundle {
            signed_prekey: PublicSignedPrekey::from(&self.signed_prekey),
            kem_prekey: PublicSignedMlKemPrekey::from(&self.last_resort_kem),
            identity_pk: self.identity_pk,
            one_time_prekey: None,
            one_time_prekey_id: None,
            kem_id: self.last_resort_id,
        };

        if let Some(signed_prekey) = one_time_prekey {
            bundle.one_time_prekey_id = Some(signed_prekey.0.clone());
            bundle.one_time_prekey = Some(PublicSignedPrekey::from(&signed_prekey.1.key));
        }

        bundle
    }
}

impl PrekeyBundle {
    pub fn new(
        signed_prekey: PublicSignedPrekey,
        kem_prekey: PublicSignedMlKemPrekey,
        identity_pk: ed25519::VerifyingKey,
        one_time_prekey: Option<PublicSignedPrekey>,
        one_time_prekey_id: Option<u32>,
        kem_id: KemId,
    ) -> Self {
        PrekeyBundle {
            signed_prekey,
            kem_prekey,
            identity_pk,
            one_time_prekey,
            one_time_prekey_id,
            kem_id,
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
