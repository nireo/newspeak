use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    newspeak::client::run().await
}
