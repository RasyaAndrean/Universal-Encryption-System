#[allow(dead_code)]
mod audit;
mod cli;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod crypto;
#[allow(dead_code)]
mod format;
#[allow(dead_code)]
mod hardware;
#[allow(dead_code)]
mod security;
#[allow(dead_code)]
mod signature;

use anyhow::Result;

fn main() -> Result<()> {
    cli::run()
}
