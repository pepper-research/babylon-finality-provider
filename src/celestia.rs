use celestia_rpc::{client::Client, HeaderClient};
use celestia_types::ExtendedHeader;
use std::env;

pub async fn get_client() -> Result<Client, String> {
    let rpc = env::var("CELESTIA_RPC")
        .map_err(|e| format!("could not read env variable: CELESTIA_RPC: {e}"))?;
    Client::new(&rpc, None)
        .await
        .map_err(|e| format!("could not create celestia rpc client: {e}"))
}

pub async fn get_block_header(height: u64) -> Result<ExtendedHeader, String> {
    get_client()
        .await?
        .header_get_by_height(height)
        .await
        .map_err(|e| format!("could not fetch header for block {height}: {e}"))
}
