use anyhow::{anyhow, Result};
use cosmrs::{crypto::secp256k1::SigningKey, tendermint::chain, AccountId, Coin, Denom};
use once_cell::sync::Lazy;
use rand_core::OsRng;
use std::{fs, path::PathBuf, str::FromStr};

pub const BABYLON_ACCOUNT_ID_PREFIX: &str = "bbn";

pub static BABYLON_DENOM: Lazy<Denom> = Lazy::new(|| match Denom::from_str("ubbn") {
    Ok(denom) => denom,
    Err(e) => panic!("could not create denom: {e}"),
});

pub static BABYLON_CHAIN_ID: Lazy<chain::Id> =
    Lazy::new(|| match chain::Id::from_str("euphrates-0.5.0") {
        Ok(id) => id,
        Err(e) => panic!("could not parse chain id: {e}"),
    });

pub fn babylon_coin(amount: u128) -> Coin {
    Coin {
        amount,
        denom: Lazy::force(&BABYLON_DENOM).clone(),
    }
}

pub trait BabylonAccountId {
    fn babylon_account_id(&self) -> AccountId;
}

impl BabylonAccountId for SigningKey {
    fn babylon_account_id(&self) -> AccountId {
        match self.public_key().account_id(BABYLON_ACCOUNT_ID_PREFIX) {
            Ok(account_id) => account_id,
            Err(e) => panic!("could not create babylon account id: {e}"),
        }
    }
}

pub fn get_or_create_keypair(path: &PathBuf) -> Result<SigningKey> {
    if let Ok(keypair_json) = fs::read_to_string(path) {
        return SigningKey::from_slice(&serde_json::from_str::<Vec<u8>>(&keypair_json)?)
            .map_err(|e| anyhow!("could not parse {} as keypair: {e}", path.display()));
    }
    eprintln!("could not read keypair at {}, creating new", path.display());

    let signer = k256::ecdsa::SigningKey::random(&mut OsRng);
    fs::write(path, serde_json::to_vec(signer.to_bytes().as_slice())?)?;
    Ok(SigningKey::new(Box::new(signer)))
}

pub fn get_keypair(path: &PathBuf) -> Result<SigningKey> {
    let keypair_json = fs::read_to_string(path)?;
    SigningKey::from_slice(serde_json::from_str(&keypair_json)?)
        .map_err(|e| anyhow!("could not parse {} as keypair: {e}", path.display()))
}
