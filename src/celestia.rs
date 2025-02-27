use anyhow::{anyhow, Result};
use celestia_rpc::{client::Client, HeaderClient};
use celestia_types::ExtendedHeader;
use std::env;


pub async fn get_client() -> Result<Client> {
    let rpc = env::var("CELESTIA_RPC")?;
    Client::new(&rpc, None)
        .await
        .map_err(|e| anyhow!("could not create celestia rpc client: {e}"))
}

pub async fn get_block_header(height: u64) -> Result<ExtendedHeader> {
    get_client()
        .await?
        .header_get_by_height(height)
        .await
        .map_err(|e| anyhow!("could not fetch header for block {height}: {e}"))
}

pub async fn get_latest_block_height() -> Result<u64> {
    let header = get_client().await?
        .header_network_head()
        .await
        .map_err(|e| anyhow!("could not fetch latest block header: {e}"))?;

    Ok(header.height().value())
}