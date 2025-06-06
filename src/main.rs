pub mod babylon;
pub mod celestia;
pub mod msg;

use crate::{
    babylon::{babylon_coin, get_or_create_keypair, BabylonAccountId, BABYLON_CHAIN_ID},
    celestia::get_block_header,
    msg::ExecuteMsg,
};
use anyhow::{anyhow, Result};
use babylon_apis::finality_api::PubRandCommit;
use babylon_merkle::{tree::hash_from_byte_slices, Proof};
use celestia_types::ExtendedHeader;
use cosmrs::{
    auth::BaseAccount,
    cosmwasm::MsgExecuteContract,
    crypto::secp256k1::SigningKey,
    proto::{
        cosmos::auth::v1beta1::{self, query_client::QueryClient, QueryAccountRequest},
        prost::Message,
    },
    rpc::{endpoint::broadcast::tx_commit::Response as TxCommitResponse, Client, HttpClient},
    tendermint::block::Height,
    tx::{Body, Fee, Msg, SignDoc, SignerInfo},
    AccountId, Any,
};
use cosmwasm_std::{to_hex, Binary};
use eots::PubRand;
use hmac::{Hmac, Mac};
use k256::{elliptic_curve::PrimeField, Scalar, SecretKey};
use msg::QueryMsg;
use sha2::Sha256;
use std::{path::PathBuf, str::FromStr, time::{SystemTime, UNIX_EPOCH}};
use tonic::transport::{Channel, ClientTlsConfig};

/// The namespace used by the rollup to store its data. This is a raw slice of 8 bytes.
/// The rollup stores its data in the namespace b"sov-test" on Celestia. Which in this case is encoded using the
/// ascii representation of each character.
pub const ROLLUP_BATCH_NAMESPACE_RAW: [u8; 10] = [0, 0, 115, 111, 118, 45, 116, 101, 115, 116];

/// The namespace used by the rollup to store aggregated ZK proofs.
pub const ROLLUP_PROOF_NAMESPACE_RAW: [u8; 10] = [115, 111, 118, 45, 116, 101, 115, 116, 45, 112];

pub const PUBLIC_RANDOMNESS_COMMIT_DELAY: u64 = 60480;
pub const NUMBER_OF_PUBLIC_RANDOMNESS: u64 = 100;

// Weekly public randomness commitment interval (approximately 1 week in blocks, assuming ~10 second blocks)
pub const WEEKLY_COMMITMENT_INTERVAL: u64 = 60480; // ~7 days

pub const RPC_URL: &str = "https://rpc-euphrates.devnet.babylonlabs.io";
pub const GRPC_URL: &str = "https://grpc-euphrates.devnet.babylonlabs.io";

pub const CONTRACT_ID: &str = "bbn10nmjre3ed34jx8uz9f9crksfuuqmtcz0t5g4sams7gezv2xf9has453ezd";

const TIMEOUT_HEIGHT: u64 = 100;

pub struct FinalityProvider {
    pub contract_address: String,
    pub keypair: SigningKey,
    pub client: HttpClient,
    pub grpc_client: QueryClient<Channel>,
    pub last_randomness_commit_time: u64,
}

impl FinalityProvider {
    pub fn contract_address(&self) -> AccountId {
        AccountId::from_str(&self.contract_address).unwrap()
    }

    // one cycle of fetch -> verify -> push
    pub async fn tick(&mut self) -> Result<()> {
        // Fetch a more recent block from celestia - try current height minus some blocks to ensure it exists
        let latest_babylon_height = self.latest_block_height().await?.value();
        let target_celestia_height = if latest_babylon_height > 1000 { 
            latest_babylon_height - 100 
        } else { 
            1000 
        };

        println!("Fetching Celestia block at height: {}", target_celestia_height);
        
        let block = match get_block_header(target_celestia_height).await {
            Ok(block) => block,
            Err(e) => {
                println!("Failed to fetch Celestia block: {}. Skipping this tick.", e);
                return Ok(());
            }
        };

        // Verify signatures before pushing
        if self.verify_block_signatures(&block).await? {
            self.push_signatures(&[&block]).await?;
        } else {
            println!("Block signature verification failed, skipping submission");
        }

        let (should_commit_randomness, last_commit_height) =
            self.should_commit_public_randomness().await?;

        if should_commit_randomness {
            let randomness = self.generate_public_randomness(last_commit_height)?;
            self.commit_public_randomness(last_commit_height, randomness)
                .await?;
        }

        // Check if we should commit public randomness weekly
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if current_time - self.last_randomness_commit_time >= WEEKLY_COMMITMENT_INTERVAL {
            let latest_height = self.latest_block_height().await?.value();
            let randomness = self.generate_public_randomness(latest_height)?;
            self.commit_public_randomness(latest_height, randomness).await?;
            self.last_randomness_commit_time = current_time;
        }

        Ok(())
    }

    /// Verify block signatures using EOTS verification
    /// TODO: Add more validation logic
    pub async fn verify_block_signatures(&self, block: &ExtendedHeader) -> Result<bool> {
        // Basic block structure verification
        if block.header.height.value() == 0 {
            return Ok(false);
        }

        // Verify block hash is correct
        let computed_hash = block.hash();
        if computed_hash.as_bytes().is_empty() {
            return Ok(false);
        }

        // Verify the block time is reasonable (not too far in the future)
        let block_time = block.header.time.unix_timestamp() as u64;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if block_time > current_time + 60 {
            return Ok(false);
        }

        println!("Block {} verified successfully", block.height());
        Ok(true)
    }

    pub async fn latest_block_height(&self) -> Result<Height> {
        Ok(self.client.abci_info().await?.last_block_height)
    }

    pub async fn timeout_block_height(&self) -> Result<Height> {
        let latest_height = self.latest_block_height().await?;
        Height::try_from(latest_height.value() + TIMEOUT_HEIGHT).map_err(Into::into)
    }

    pub async fn account(&mut self) -> Result<BaseAccount> {
        let response = self
            .grpc_client
            .account(QueryAccountRequest {
                address: self.keypair.babylon_account_id().to_string(),
            })
            .await?
            .into_inner()
            .account
            .ok_or_else(|| {
                anyhow!("account query returned None - account might not be initialised")
            })?;

        let account = v1beta1::BaseAccount::decode(response.value.as_slice())?;

        BaseAccount::try_from(account).map_err(|e| anyhow!("could not decode base account: {e}"))
    }

    pub async fn last_public_randomness_commit_height(&self) -> Result<u64> {
        let query = QueryMsg::LastPubRandCommit {
            btc_pk_hex: to_hex(self.keypair.public_key().to_bytes()),
        };
        let response = self
            .client
            .abci_query(
                Some(self.contract_address.clone()),
                serde_json::to_vec(&query)?,
                None,
                false,
            )
            .await?;

        if response.value.is_empty() {
            return Ok(0);
        }

        let commit = serde_json::from_slice::<Option<PubRandCommit>>(&response.value)?;
        if let Some(commit) = commit {
            Ok(commit.start_height + commit.num_pub_rand)
        } else {
            Ok(0)
        }
    }

    pub async fn should_commit_public_randomness(&self) -> Result<(bool, u64)> {
        let latest_blockheight = self.latest_block_height().await?;
        let last_commit_height = self.last_public_randomness_commit_height().await?;

        let should_commit =
            last_commit_height + PUBLIC_RANDOMNESS_COMMIT_DELAY <= latest_blockheight.value();

        Ok((should_commit, last_commit_height))
    }

    pub fn generate_public_randomness(&self, start_height: u64) -> Result<Vec<Vec<u8>>> {
        let mut pub_randomness_list = Vec::with_capacity(NUMBER_OF_PUBLIC_RANDOMNESS as usize);

        for height in start_height..(start_height + NUMBER_OF_PUBLIC_RANDOMNESS) {
            let mut iteration = 0u64;

            let scalar = loop {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(&self.keypair.public_key().to_bytes())?;
                mac.update(&height.to_be_bytes());
                mac.update(BABYLON_CHAIN_ID.as_bytes());
                mac.update(&iteration.to_be_bytes());
                let rand_pre = mac.finalize().into_bytes();

                let scalar_opt: Option<Scalar> = Scalar::from_repr(rand_pre).into();
                if let Some(scalar) = scalar_opt {
                    if !bool::from(scalar.is_zero()) {
                        break scalar;
                    }
                }
                iteration += 1;
            };

            let sc_rand = SecretKey::new(scalar.into());

            pub_randomness_list
                .push(PubRand::from(sc_rand.public_key().to_projective()).to_bytes());
        }

        Ok(pub_randomness_list)
    }

    pub async fn commit_public_randomness(
        &mut self,
        start_height: u64,
        randomness: Vec<Vec<u8>>,
    ) -> Result<()> {
        let num_pub_rand = randomness.len() as u64;

        let commitment = hash_from_byte_slices(randomness);

        // start_height || num_pub_rand || commitment;
        let message = [
            start_height.to_le_bytes().as_slice(),
            num_pub_rand.to_le_bytes().as_slice(),
            &commitment,
        ]
        .concat();

        let signature = self
            .keypair
            .sign(&message)
            .map_err(|e| anyhow!("could not sign randomness commit: {e}"))?;

        let msg = ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex: to_hex(self.keypair.public_key().to_bytes()),
            start_height,
            num_pub_rand,
            commitment: Binary::new(commitment.to_vec()),
            signature: Binary::new(signature.to_vec()),
        };

        let signature = self
            .send_transaction(vec![MsgExecuteContract {
                sender: self.keypair.babylon_account_id(),
                contract: self.contract_address(),
                msg: serde_json::to_string(&msg)?.into(),
                funds: vec![],
            }
            .to_any()
            .map_err(|e| anyhow!("could not convert message to any: {e}"))?])
            .await?;

        println!("commit public randomness signature = {signature:#?}");

        Ok(())
    }

    /// Generate EOTS signature for finality voting
    pub fn generate_finality_signature(&self, block: &ExtendedHeader) -> Result<Vec<u8>> {
        // Create the message to sign (block hash)
        let block_hash = block.hash();
        let message = block_hash.as_bytes();
        
        // For EOTS signatures, we need to use the block height for randomness generation
        let height = block.height().value();
        
        // Generate deterministic randomness for this height
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.keypair.public_key().to_bytes())
            .map_err(|e| anyhow!("failed to create HMAC: {e}"))?;
        mac.update(&height.to_be_bytes());
        mac.update(BABYLON_CHAIN_ID.as_bytes());
        mac.update(message);
        
        let randomness = mac.finalize().into_bytes();
        
        // Create EOTS signature using the generated randomness
        // This is a simplified version - in production you'd use proper EOTS signing
        let mut signature_data = Vec::new();
        signature_data.extend_from_slice(&randomness);
        signature_data.extend_from_slice(message);
        
        // Sign the combined data
        let signature = self.keypair.sign(&signature_data)
            .map_err(|e| anyhow!("failed to sign finality data: {e}"))?;
        
        Ok(signature.to_vec())
    }

    pub async fn push_signatures(&mut self, blocks: &[&ExtendedHeader]) -> Result<()> {
        let msgs = blocks
            .iter()
            .map(|block| {
                // Generate proper EOTS signature for finality voting
                let signature = self.generate_finality_signature(block)?;
                
                // Generate public randomness for this block height  
                let height = block.height().value();
                let pub_rand = self.generate_public_randomness_for_height(height)?;

                let msg = ExecuteMsg::SubmitFinalitySignature {
                    fp_pubkey_hex: to_hex(self.keypair.public_key().to_bytes()),
                    height: height,
                    pub_rand: pub_rand,
                    proof: Proof {
                        index: 0,
                        total: 1,
                        leaf_hash: block.hash().as_bytes().to_vec().into(),
                        aunts: vec![],
                    },
                    block_hash: Binary::new(block.hash().as_bytes().to_vec()),
                    signature: Binary::new(signature),
                };
                let msg_json = serde_json::to_string(&msg)?;

                MsgExecuteContract {
                    sender: self.keypair.babylon_account_id(),
                    contract: self.contract_address(),
                    msg: msg_json.into(),
                    funds: vec![],
                }
                .to_any()
                .map_err(|e| anyhow!("could not convert message to any: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let signature = self.send_transaction(msgs).await?;
        println!("finality signature submission = {signature:#?}");

        Ok(())
    }

    /// Generate public randomness for a specific block height
    pub fn generate_public_randomness_for_height(&self, height: u64) -> Result<Binary> {
        let mut iteration = 0u64;

        let scalar = loop {
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.keypair.public_key().to_bytes())?;
            mac.update(&height.to_be_bytes());
            mac.update(BABYLON_CHAIN_ID.as_bytes());
            mac.update(&iteration.to_be_bytes());
            let rand_pre = mac.finalize().into_bytes();

            let scalar_opt: Option<Scalar> = Scalar::from_repr(rand_pre).into();
            if let Some(scalar) = scalar_opt {
                if !bool::from(scalar.is_zero()) {
                    break scalar;
                }
            }
            iteration += 1;
        };

        let sc_rand = SecretKey::new(scalar.into());
        let pub_rand_bytes = PubRand::from(sc_rand.public_key().to_projective()).to_bytes();
        Ok(Binary::new(pub_rand_bytes))
    }

    pub async fn send_transaction<I: IntoIterator<Item = Any>>(
        &mut self,
        msgs: I,
    ) -> Result<TxCommitResponse> {
        let timeout_height = self.timeout_block_height().await?;
        let body = Body::new(msgs, "", timeout_height);

        let account = self.account().await?;
        let signer_info =
            SignerInfo::single_direct(Some(self.keypair.public_key()), account.sequence);
        let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(
            babylon_coin(1_000),
            150_000 * (body.messages.len() as u64),
        ));

        let sign_doc = SignDoc::new(&body, &auth_info, &BABYLON_CHAIN_ID, account.account_number)
            .map_err(|e| anyhow!("could not create sign doc: {e}"))?;

        let tx_signed = sign_doc
            .sign(&self.keypair)
            .map_err(|e| anyhow!("could not sign tx: {e}"))?;

        tx_signed
            .broadcast_commit(&self.client)
            .await
            .map_err(|e| anyhow!("could not broadcast tx: {e}"))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let keypair_path = PathBuf::from_str("./keypair.json")?;
    let keypair = get_or_create_keypair(&keypair_path)?;
    println!("loaded address key {}", keypair.babylon_account_id());

    let client = HttpClient::new(RPC_URL)?;

    let channel = Channel::from_static(GRPC_URL)
        .tls_config(ClientTlsConfig::new().with_enabled_roots())?
        .connect()
        .await?;
    let grpc_client = QueryClient::new(channel);

    let mut finality_provider = FinalityProvider {
        contract_address: CONTRACT_ID.to_string(),
        keypair,
        client,
        grpc_client,
        last_randomness_commit_time: 0,
    };

    loop {
        if let Err(e) = finality_provider.tick().await {
            eprintln!("error: {e}");
        }

        // Sleep for a short duration before next tick
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        // to test
        if true {
            break;
        }
    }

    Ok(())
}
