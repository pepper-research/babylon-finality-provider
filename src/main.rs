pub mod babylon;
pub mod celestia;
mod config;
mod eots;
mod fp_merkle;
mod kvdb_proof;
pub mod msg;

use crate::{
    babylon::{babylon_coin, get_or_create_keypair, BabylonAccountId, BABYLON_CHAIN_ID},
    celestia::{get_block_header, get_latest_block_height},
    config::{Config, DatabaseBackend, StorageConfig},
    kvdb_proof::{create_persistent_db, ProofStore, PubRandProofStore},
    msg::ExecuteMsg,
};

use crate::kvdb_proof::create_memory_db;
use anyhow::{anyhow, Context, Result};
use babylon_merkle::Proof;
// use celestia_rpc::HeaderClient;
use babylon_merkle::tree::hash_from_byte_slices;
use celestia_types::ExtendedHeader;
use cosmrs::{
    auth::BaseAccount,
    cosmwasm::MsgExecuteContract,
    crypto::{secp256k1::Signature, secp256k1::SigningKey},
    proto::{
        cosmos::auth::v1beta1::{self, query_client::QueryClient, QueryAccountRequest},
        prost::Message,
    },
    rpc::{Client, HttpClient},
    tendermint::block::Height,
    tx::{Body, Fee, Msg, SignDoc, SignerInfo},
    AccountId,
};
use cosmwasm_std::{to_hex, Binary};
use kvdb::KeyValueDB;
use std::sync::Arc;
use std::{path::PathBuf, str::FromStr};
use k256::schnorr::signature::SignatureEncoding;
use tonic::transport::{Channel, ClientTlsConfig};

/// The namespace used by the rollup to store its data. This is a raw slice of 8 bytes.
/// The rollup stores its data in the namespace b"sov-test" on Celestia. Which in this case is encoded using the
/// ascii representation of each character.
pub const ROLLUP_BATCH_NAMESPACE_RAW: [u8; 10] = [0, 0, 115, 111, 118, 45, 116, 101, 115, 116];

/// The namespace used by the rollup to store aggregated ZK proofs.
pub const ROLLUP_PROOF_NAMESPACE_RAW: [u8; 10] = [115, 111, 118, 45, 116, 101, 115, 116, 45, 112];

pub const RPC_URL: &str = "https://rpc-euphrates.devnet.babylonlabs.io";
pub const GRPC_URL: &str = "https://grpc-euphrates.devnet.babylonlabs.io";

pub const CONTRACT_ID: &str = "bbn10nmjre3ed34jx8uz9f9crksfuuqmtcz0t5g4sams7gezv2xf9has453ezd";

const TIMEOUT_HEIGHT: u64 = 100;

pub struct FinalityProvider {
    pub contract_address: String,
    pub keypair: SigningKey,
    pub client: HttpClient,
    pub grpc_client: QueryClient<Channel>,
    pub config: Config,
    pub store: Arc<dyn ProofStore>,
    pub eots: Arc<eots::EotsManager>,
}

impl FinalityProvider {
    pub fn new(
        contract_address: String,
        keypair: SigningKey,
        client: HttpClient,
        grpc_client: QueryClient<Channel>,
        config: Config,
    ) -> Result<Self> {
        let db = Self::create_db(&config.storage).context("Failed to initialize database")?;
        let store = Arc::new(PubRandProofStore::new(db));
        let eots = Arc::new(eots::EotsManager::new());

        Ok(Self {
            contract_address,
            keypair,
            client,
            grpc_client,
            config,
            store,
            eots,
        })
    }

    fn create_db(storage_config: &StorageConfig) -> Result<Arc<dyn KeyValueDB>> {
        match storage_config.backend {
            DatabaseBackend::RocksDB => Ok(create_persistent_db(storage_config)?),
            DatabaseBackend::Memory => Ok(create_memory_db(storage_config.columns)?),
        }
    }

    pub async fn push_public_rand(&mut self, chain_id: &[u8], height: u64) -> Result<()> {
        let pub_rand_list = self.generate_randomness_pairs(chain_id, height)?;
        let commitment = hash_from_byte_slices(pub_rand_list);
        // Dmitry: I will skip storing proofs in local layer for now
        let pub_key = self.get_public_key_bytes()?;

        let schnorr_sig = self.eots.sign(&pub_key, height, self.config.num_pub_rand, &commitment)?;

        let msg = ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex: to_hex(self.keypair.public_key().to_bytes()),
            start_height: height,
            num_pub_rand: self.config.num_pub_rand,
            signature: Binary::new(schnorr_sig.to_vec()),
            commitment: Binary::new(commitment),
        };

        let msg_json = serde_json::to_string(&msg)?;

        let contract = MsgExecuteContract {
            sender: self.keypair.babylon_account_id(),
            contract: self.contract_address(),
            msg: msg_json.into(),
            funds: vec![],
        }.to_any()
            .map_err(|e| anyhow!("could not convert message to any: {e}"))?;

        let msgs = vec![contract];

        let account = self.account().await?;
        let signer_info =
            SignerInfo::single_direct(Some(self.keypair.public_key()), account.sequence);
        let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(
            babylon_coin(1_000),
            150_000 * (msgs.len() as u64),
        ));

        let timeout_height = self.timeout_block_height().await?;
        let body = Body::new(msgs, "", timeout_height);

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

    fn get_public_key_bytes(&self) -> Result<[u8; 32]> {
        self.keypair.public_key().to_bytes().try_into()
            .map_err(|_| anyhow::anyhow!("Public key must be exactly 32 bytes"))
    }

    fn generate_randomness_pairs(&self, chain_id: &[u8], height: u64) -> Result<Vec<Vec<u8>>> {
        let pub_key = self.get_public_key_bytes()?;
        self.eots.generate_randomness_pairs(&pub_key, chain_id, height, self.config.num_pub_rand)
            .context("Failed to generate randomness pairs")
            .map(|pairs| pairs.into_iter().map(|pair| pair.to_vec()).collect())
    }

    pub fn contract_address(&self) -> AccountId {
        AccountId::from_str(&self.contract_address).unwrap()
    }

    // one cycle of fetch -> verify -> push
    pub async fn tick(&mut self) -> Result<()> {
        // fetch block from celestia

        let latest = get_latest_block_height().await?;
        println!("Latest block height: {}", latest);

        let block = get_block_header(2547000).await?;
        self.push_signatures(&[&block]).await?;

        // TODO: verify signatures
        // TODO: push signatures to babylon contract via rpc

        Ok(())
    }

    // By default, using k256::ecdsa::SigningKey to sign the block hash
    fn create_signatures(&self, block_hash: &[u8]) -> Result<Signature> {
        self.keypair
            .sign(block_hash)
            .map_err(|e| anyhow!("could not sign block hash: {e}"))
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

    pub async fn push_signatures(&mut self, blocks: &[&ExtendedHeader]) -> Result<()> {
        let msgs = blocks
            .iter()
            .map(|block| {
                let msg = ExecuteMsg::SubmitFinalitySignature {
                    fp_pubkey_hex: to_hex(self.keypair.public_key().to_bytes()),
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
            babylon_coin(1_000),
            150_000 * (msgs.len() as u64),
        ));

        let timeout_height = self.timeout_block_height().await?;
        let body = Body::new(msgs, "", timeout_height);

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

    let channel = Channel::from_static(GRPC_URL)
        .tls_config(ClientTlsConfig::new().with_enabled_roots())?
        .connect()
        .await?;
    let grpc_client = QueryClient::new(channel);

    let config = Config {
        storage: StorageConfig {
            backend: DatabaseBackend::RocksDB,
            path: "./db".into(),
            columns: 1,
        },
        num_pub_rand: 100,
    };

    let mut finality_provider = FinalityProvider::new(
        CONTRACT_ID.to_string(),
        keypair,
        client,
        grpc_client,
        config,
    )?;

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
