pub mod celestia;
pub mod msg;

use crate::msg::ExecuteMsg;
use babylon_merkle::Proof;
use celestia::get_block_header;
use cosmrs::{
    cosmwasm::MsgExecuteContract,
    tx::{Body, Msg},
    AccountId, Tx,
};
use cosmwasm_std::Binary;
use std::{fmt::format, str::FromStr};

/// The namespace used by the rollup to store its data. This is a raw slice of 8 bytes.
/// The rollup stores its data in the namespace b"sov-test" on Celestia. Which in this case is encoded using the
/// ascii representation of each character.
pub const ROLLUP_BATCH_NAMESPACE_RAW: [u8; 10] = [0, 0, 115, 111, 118, 45, 116, 101, 115, 116];

/// The namespace used by the rollup to store aggregated ZK proofs.
pub const ROLLUP_PROOF_NAMESPACE_RAW: [u8; 10] = [115, 111, 118, 45, 116, 101, 115, 116, 45, 112];

const TIMEOUT_HEIGHT: u16 = 9001;

fn contract_address() -> AccountId {
    AccountId::from_str("").unwrap()
}

fn push_signatures(signatures: &[&str]) -> Result<(), String> {
    let msgs = signatures
        .iter()
        .map(|signature| -> Result<_, String> {
            let msg = ExecuteMsg::SubmitFinalitySignature {
                fp_pubkey_hex: "".to_string(),
                height: 0,
                pub_rand: Default::default(),
                proof: Proof {
                    index: Default::default(),
                    total: Default::default(),
                    leaf_hash: Default::default(),
                    aunts: Default::default(),
                },
                block_hash: Default::default(),
                signature: Binary::new(signature.as_bytes().into()),
            };
            MsgExecuteContract {
                // TODO
                sender: AccountId::from_str("").unwrap(),
                contract: contract_address(),
                msg: bincode::serialize(&msg)
                    .map_err(|e| format!("could not serialize message: {e}"))?,
                funds: vec![],
            }
            .to_any()
            .map_err(|e| format!("error converting MsgExecuteContract to any: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let body = Body::new(msgs, "", TIMEOUT_HEIGHT);
    // TODO: sign and send transaction

    Ok(())
}

// one cycle of fetch -> verify -> push
async fn tick() -> Result<(), String> {
    // fetch block from celestia
    let block = get_block_header(2547000).await?;

    // TODO: verify signatures

    // TODO: push signatures to babylon contract via rpc

    Ok(())
}

#[tokio::main]
async fn main() {
    loop {
        if let Err(e) = tick().await {
            eprint!("error: {e}");
        }

        // TODO: once a week, commit public randomness

        break;
    }
}
