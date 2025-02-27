use anyhow::{anyhow, Result};

use hmac::{Hmac, Mac};
use rand_core::OsRng;

use k256::{
    elliptic_curve::{
        PrimeField,
        subtle::CtOption,
        point::AffineCoordinates,
    },
    schnorr::{Signature, SigningKey as SchnorrSigningKey},
    FieldBytes,
    NonZeroScalar,
    PublicKey as K256PublicKey,
    Scalar,
    schnorr::signature::Signer
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

/// BIP-340 Compliant Public Key (X-only)
type BIP340PubKey = [u8; 32];

/// Represents a private randomness value (scalar)
pub type PrivateRand = Scalar;

struct KeyStore {
    // Maps (Chain ID, Block Height) to Public Key
    keys: HashMap<(Vec<u8>, u64), BIP340PubKey>,
    // Maps Public Keys to Private Keys
    key_pairs: HashMap<BIP340PubKey, SchnorrSigningKey>,
}

pub struct EotsManager {
    store: KeyStore,
}

impl EotsManager {
    pub fn new() -> Self {
        Self {
            store: KeyStore {
                keys: HashMap::new(),
                key_pairs: HashMap::new(),
            },
        }
    }

    // Generate or retrieve existing key for specific chain/height
    pub fn get_or_create_key(&mut self, chain_id: &[u8], height: u64) -> Result<BIP340PubKey> {
        // Check if key exists for this context
        if let Some(pubkey) = self.store.keys.get(&(chain_id.to_vec(), height)) {
            return Ok(*pubkey);
        }

        // Generate new key pair
        let signing_key = SchnorrSigningKey::random(&mut OsRng);

        // Get the verifying key and convert to bytes
        let bip340_pubkey = signing_key
            .verifying_key()
            .to_bytes()
            .try_into()
            .map_err(|_| anyhow!("Failed to convert public key to BIP340 format"))?;

        // Store with context
        self.store
            .keys
            .insert((chain_id.to_vec(), height), bip340_pubkey);

        self.store.key_pairs.insert(bip340_pubkey, signing_key);

        Ok(bip340_pubkey)
    }

    // Sign message with BIP-340 Schnorr signature
    pub fn sign(
        &self,
        pubkey: &BIP340PubKey,
        start_height: u64,
        num_pub_rnd: u64,
        msg: &[u8],
    ) -> Result<Signature> {
        let schnorr_key = self
            .store
            .key_pairs
            .get(pubkey)
            .ok_or(anyhow!("Key not found"))?;

        let mut hasher = Sha256::new();
        hasher.update(start_height.to_be_bytes());
        hasher.update(num_pub_rnd.to_be_bytes());
        hasher.update(msg);
        let hash = hasher.finalize().to_vec();

        Ok(schnorr_key.sign(&hash))
    }

    pub fn generate_randomness_pairs(
        &self,
        pubkey: &BIP340PubKey,
        chain_id: &[u8],
        start_height: u64,
        num: u64,
    ) -> Result<Vec<BIP340PubKey>> {
        let signing_key = self
            .store
            .key_pairs
            .get(pubkey)
            .ok_or(anyhow!("Key not found"))?;
        let privkey_bytes = signing_key.to_bytes();

        let mut pr_list = Vec::with_capacity(num as usize);

        for i in 0..num {
            let height = start_height + i as u64;
            let (_, pub_rand) = generate_randomness(&privkey_bytes, chain_id, height);
            pr_list.push(pub_rand);
        }

        Ok(pr_list)
    }
}

fn generate_randomness(
    privkey: &[u8],
    chain_id: &[u8],
    height: u64,
) -> (PrivateRand, BIP340PubKey) {
    let mut iteration = 0u64;

    loop {
        let mut hmac = HmacSha256::new_from_slice(privkey).unwrap();
        hmac.update(&height.to_be_bytes());
        hmac.update(chain_id);
        hmac.update(&iteration.to_be_bytes());

        let rand_pre = hmac.finalize().into_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&rand_pre[..32]);

        let scalar_opt = bytes_to_scalar(bytes).into_option();

        match scalar_opt {
            Some(scalar) if !bool::from(scalar.is_zero()) => {
                let scalar_non_zero = &NonZeroScalar::new(scalar).unwrap();
                let public_rand = K256PublicKey::from_secret_scalar(scalar_non_zero);
                let x = public_rand.as_affine().x();
                return (scalar, x.into());
            }
            _ => iteration += 1,
        }
    }
}

fn bytes_to_scalar(bytes: [u8; 32]) -> CtOption<Scalar> {
    // 1. Convert bytes to FieldBytes (SEC1 encoding)
    let field_bytes = FieldBytes::from(bytes);

    // 2. Use from_repr for proper conversion
    Scalar::from_repr(field_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_randomness() {
        let privkey = [0u8; 32];
        let chain_id = [0u8; 32];
        let height = 0u64;

        let (priv_rand, pub_rand) = generate_randomness(&privkey, &chain_id, height);

        // Check that private randomness is not zero
        assert!(
            !bool::from(priv_rand.is_zero()),
            "Private randomness should not be zero"
        );

        // Check that public randomness is 32 bytes long
        assert_eq!(
            pub_rand.len(),
            32,
            "Public randomness should be 32 bytes long"
        );

        // Check that generating randomness twice with the same inputs produces the same result
        let (priv_rand2, pub_rand2) = generate_randomness(&privkey, &chain_id, height);
        assert_eq!(
            priv_rand, priv_rand2,
            "Private randomness should be deterministic"
        );
        assert_eq!(
            pub_rand, pub_rand2,
            "Public randomness should be deterministic"
        );

        // Check that different inputs produce different results
        let (priv_rand3, pub_rand3) = generate_randomness(&privkey, &chain_id, height + 1);
        assert_ne!(
            priv_rand, priv_rand3,
            "Different inputs should produce different private randomness"
        );
        assert_ne!(
            pub_rand, pub_rand3,
            "Different inputs should produce different public randomness"
        );

        // Verify that the public key is on the curve
        // let point = ProjectivePoint::from_bytes(&pub_rand);
        // assert!(bool::from(point.is_some()), "Public randomness should represent a valid curve point");
    }
}
