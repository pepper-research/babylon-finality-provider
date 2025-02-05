pub mod babylon;
pub mod celestia;
pub mod msg;

use crate::{
    babylon::{babylon_coin, get_or_create_keypair, BabylonAccountId, BABYLON_CHAIN_ID},
    celestia::get_block_header,
    msg::ExecuteMsg,
};
use anyhow::{anyhow, Result};
use babylon_merkle::Proof;
use celestia_types::ExtendedHeader;
use cosmrs::{
    auth::BaseAccount,
    cosmwasm::MsgExecuteContract,
    crypto::secp256k1::SigningKey,
    proto::prost::Message,
    rpc::HttpClient,
    tx::{Body, Fee, Msg, SignDoc, SignerInfo},
    AccountId,
};
use cosmwasm_std::Binary;
use std::{path::PathBuf, str::FromStr};

/// The namespace used by the rollup to store its data. This is a raw slice of 8 bytes.
/// The rollup stores its data in the namespace b"sov-test" on Celestia. Which in this case is encoded using the
/// ascii representation of each character.
pub const ROLLUP_BATCH_NAMESPACE_RAW: [u8; 10] = [0, 0, 115, 111, 118, 45, 116, 101, 115, 116];

/// The namespace used by the rollup to store aggregated ZK proofs.
pub const ROLLUP_PROOF_NAMESPACE_RAW: [u8; 10] = [115, 111, 118, 45, 116, 101, 115, 116, 45, 112];

pub const RPC_URL: &str = "https://rpc-euphrates.devnet.babylonlabs.io";
pub const GRPC_URL: &str = "grpc-euphrates.devnet.babylonlabs.io:443";

pub const CONTRACT_ID: &str = "bbn10nmjre3ed34jx8uz9f9crksfuuqmtcz0t5g4sams7gezv2xf9has453ezd";

const TIMEOUT_HEIGHT: u16 = 9001;

pub struct FinalityProvider {
    pub contract_address: String,
    pub keypair: SigningKey,
    pub client: HttpClient,
    pub grpc_endpoint: String,
}

impl FinalityProvider {
    pub fn contract_address(&self) -> AccountId {
        AccountId::from_str(&self.contract_address).unwrap()
    }

    // one cycle of fetch -> verify -> push
    pub async fn tick(&self) -> Result<()> {
        // fetch block from celestia
        let block = get_block_header(2547000).await?;

        self.push_signatures(&[&block]).await?;

        // TODO: verify signatures

        // TODO: push signatures to babylon contract via rpc

        Ok(())
    }

    pub async fn account(&self) -> Result<BaseAccount> {
        use cosmrs::proto::cosmos::auth::v1beta1::{query_client, QueryAccountRequest};

        let response = query_client::QueryClient::connect(self.grpc_endpoint.to_string())
            .await?
            .account(QueryAccountRequest {
                address: self.keypair.public_key().to_string(),
            })
            .await?
            .into_inner()
            .account
            .ok_or_else(|| {
                anyhow!("account query returned None - account might not be initialised")
            })?;

        let account =
            cosmrs::proto::cosmos::auth::v1beta1::BaseAccount::decode(response.value.as_slice())?;

        BaseAccount::try_from(account).map_err(|e| anyhow!("could not decode base account: {e}"))
    }

    pub async fn push_signatures(&self, blocks: &[&ExtendedHeader]) -> Result<()> {
        let msgs = blocks
            .iter()
            .map(|block| {
                let msg = ExecuteMsg::SubmitFinalitySignature {
                    fp_pubkey_hex: self.keypair.public_key().to_string(),
                    height: block.height().into(),
                    pub_rand: Default::default(),
                    proof: Proof {
                        index: 0,
                        total: 0,
                        leaf_hash: Default::default(),
                        aunts: Default::default(),
                    },
                    block_hash: Binary::new(block.hash().as_bytes().to_vec()),
                    // TODO: sign data
                    signature: Binary::new(vec![]),
                };
                let msg_json = serde_json::to_string(&msg)?;

                MsgExecuteContract {
                    // TODO
                    sender: self.keypair.babylon_account_id(),
                    contract: self.contract_address(),
                    msg: msg_json.into(),
                    funds: vec![],
                }
                .to_any()
                .map_err(|e| anyhow!("could not convert message to any: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let account = self.account().await?;
        let signer_info =
            SignerInfo::single_direct(Some(self.keypair.public_key()), account.sequence);
        let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(
            babylon_coin(100_000),
            150_000 * (msgs.len() as u64),
        ));

        let body = Body::new(msgs, "", TIMEOUT_HEIGHT);

        let sign_doc = SignDoc::new(&body, &auth_info, &BABYLON_CHAIN_ID, account.account_number)
            .map_err(|e| anyhow!("could not create sign doc: {e}"))?;

        let tx_signed = sign_doc
            .sign(&self.keypair)
            .map_err(|e| anyhow!("could not sign tx: {e}"))?;

        let signature = tx_signed
            .broadcast_commit(&self.client)
            .await
            .map_err(|e| anyhow!("could not broadcast tx: {e}"))?;
        println!("signature = {signature:#?}");

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let keypair_path = PathBuf::from_str("./keypair.json")?;
    let keypair = get_or_create_keypair(&keypair_path)?;
    println!("loaded address key {}", keypair.babylon_account_id());

    let client = HttpClient::new(RPC_URL)?;

    let finality_provider = FinalityProvider {
        contract_address: CONTRACT_ID.to_string(),
        keypair,
        client,
        grpc_endpoint: GRPC_URL.to_string(),
    };

    loop {
        if let Err(e) = finality_provider.tick().await {
            eprintln!("error: {e}");
        }

        // TODO: once a week, commit public randomness

        // to test
        if true {
            break;
        }
    }

    Ok(())
}
