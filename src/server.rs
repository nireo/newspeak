mod pqxdh;
mod ratchet;

pub mod newspeak {
    tonic::include_proto!("newspeak");
}

use newspeak::newspeak_server::{Newspeak, NewspeakServer};
use newspeak::{
    FetchPrekeyBundleRequest, FetchPrekeyBundleResponse, RegisterRequest, RegisterResponse,
};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

#[derive(Default)]
struct NewspeakService;

#[tonic::async_trait]
impl Newspeak for NewspeakService {
    async fn fetch_prekey_bundle(
        &self,
        _request: Request<FetchPrekeyBundleRequest>,
    ) -> Result<Response<FetchPrekeyBundleResponse>, Status> {
        let reply = FetchPrekeyBundleResponse { bundle: None };
        Ok(Response::new(reply))
    }

    async fn register(
        &self,
        _request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let reply = RegisterResponse {
            auth_challenge: Vec::new(),
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:10000".parse()?;
    let svc = NewspeakService::default();

    println!("NewspeakServer listening on {}", addr);

    Server::builder()
        .add_service(NewspeakServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
