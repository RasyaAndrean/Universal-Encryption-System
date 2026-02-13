mod crypto;
mod signature;
mod hardware;
mod format;
mod cli;
mod security;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    cli::run().await
}