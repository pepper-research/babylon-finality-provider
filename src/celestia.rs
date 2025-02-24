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

// get latest block
// pub async fn get_latest_block() -> Result<ExtendedHeader> {
//     get_client()
//         .await?
//         .
//         .map_err(|e| anyhow!("could not fetch latest block: {e}"))
// }

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

// async fn get_latest_height(client: &(impl HeaderClient + Sync)) -> Result<u64> {
//     let header = client.header_network_head().await?;
//     Ok(header.height().value())
// }

// Mirrors GetLastCommittedHeight() in Go
// async fn get_last_committed_height() -> Result<u64> {
//     let client = get_client().await?;
//     let response = client
//         .query_last_committed_pubrand(self.btc_pubkey, 1)
//         .await?;
//
//     response.into_iter()
//         .next()
//         .map(|(start, commit)| start + commit.num_pubrand - 1)
//         .ok_or(Error::NoCommitmentsFound)
// }