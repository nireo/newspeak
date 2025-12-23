pub mod pqxdh;
pub mod newspeak {
    tonic::include_proto!("newspeak");
}

use crate::{
    newspeak::{
        FetchPrekeyBundleRequest, FetchPrekeyBundleResponse, KeyKind, RegisterRequest,
        newspeak_client::NewspeakClient,
    },
    pqxdh::KeyExchangeUser,
};
use anyhow::{Ok, Result};
use ml_kem::EncodedSizeUser;
use tonic::transport::Channel;

struct User<'a> {
    username: &'a str,
    key_info: KeyExchangeUser,
    client: NewspeakClient<Channel>,
}

impl From<&pqxdh::SignedPrekey> for newspeak::SignedPrekey {
    fn from(k: &pqxdh::SignedPrekey) -> Self {
        newspeak::SignedPrekey {
            kind: KeyKind::X25519.into(),
            key: k.public_key.as_bytes().to_vec(),
            signature: k.signature.to_vec(),
        }
    }
}

impl From<&pqxdh::SignedMlKemPrekey> for newspeak::SignedPrekey {
    fn from(k: &pqxdh::SignedMlKemPrekey) -> Self {
        newspeak::SignedPrekey {
            kind: KeyKind::MlKem1024.into(),
            key: k.encap_key.as_bytes().as_slice().to_vec(),
            signature: k.signature.to_vec(),
        }
    }
}

impl<'a> User<'a> {
    pub fn new(username: &'a str, client: NewspeakClient<Channel>) -> Self {
        User {
            username,
            key_info: pqxdh::KeyExchangeUser::new(),
            client,
        }
    }

    pub async fn register(&mut self) -> Result<()> {
        let req = RegisterRequest {
            username: self.username.into(),
            identity_key: self.key_info.identity_pk.as_bytes().to_vec(),
            signed_prekey: Some((&self.key_info.signed_prekey).into()),
            one_time_prekeys: vec![],
        };

        self.client.register(req).await?;
        Ok(())
    }

    pub async fn init_key_exchange(&mut self, other: String) -> Result<()> {
        let prekey_bundle = self
            .client
            .fetch_prekey_bundle(FetchPrekeyBundleRequest { username: other })
            .await?;

        let lol = prekey_bundle.get_ref();

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // TODO: actual persistance of client state

    println!("hello from client");
    let args: Vec<String> = std::env::args().collect();
    let client = NewspeakClient::connect("http://[::1]:10000").await?;

    let mut user = User::new(&args[1], client);

    println!("logged in as: {}", user.username);

    Ok(())
}
