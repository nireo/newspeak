pub mod pqxdh;
pub mod newspeak {
    tonic::include_proto!("newspeak");
}

use crate::{
    newspeak::{KeyKind, RegisterRequest, newspeak_client::NewspeakClient},
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
    async fn register(&self) -> Result<()> {
        let req = RegisterRequest {
            username: self.username.into(),
            identity_key: self.key_info.identity_pk.as_bytes().to_vec(),
            signed_prekey: Some((&self.key_info.signed_prekey).into()),
            one_time_prekeys: self
                .key_info
                .one_time_keys
                .iter()
                .map(Into::into)
                .collect(),
        };

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("hello from client");
    let args: Vec<String> = std::env::args().collect();
    let mut client = NewspeakClient::connect("http://[::1]:10000").await?;

    Ok(())
}
