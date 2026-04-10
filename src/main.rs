mod crypto;
mod signature;
mod hardware;
mod format;
mod cli;
mod security;
mod config;
mod audit;

use anyhow::Result;

fn main() -> Result<()> {
    cli::run()
}
