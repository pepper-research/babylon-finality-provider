use k256::{ecdsa::SigningKey, elliptic_curve::scalar::FromUintUnchecked, elliptic_curve::Field, schnorr::{
    signature::{hazmat::PrehashSigner, rand_core::CryptoRngCore},
    Signature, SigningKey as SchnorrSigningKey,
}, FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, Secp256k1, SecretKey};

use hmac::{Hmac, Mac};
use rand_chacha::ChaCha20Rng;
use rand_core::OsRng;

use k256::elliptic_curve::point::AffineCoordinates;
use k256::schnorr::signature::hazmat::RandomizedPrehashSigner;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::subtle::CtOption;
use rand::{rngs::StdRng, CryptoRng, RngCore};

use rand_chacha::rand_core::SeedableRng;

type HmacSha256 = Hmac<Sha256>;

/// BIP-340 Compliant Public Key (X-only)
type BIP340PubKey = [u8; 32];

/// Represents a private randomness value (scalar)
pub type PrivateRand = Scalar;

/// Represents a public randomness value (x-coordinate)
// pub type PublicRand = dyn k256::elliptic_curve::Field;

struct KeyStore {
    // Maps (Chain ID, Block Height) to Public Key
    keys: HashMap<(Vec<u8>, u64), BIP340PubKey>,
    // Maps Public Keys to Private Keys
    key_pairs: HashMap<BIP340PubKey, SigningKey>,
}

pub struct EOTSManager {
    store: KeyStore,
}

impl EOTSManager {
    pub fn new() -> Self {
        Self {
            store: KeyStore {
                keys: HashMap::new(),
                key_pairs: HashMap::new(),
            },
        }
    }

    // Generate or retrieve existing key for specific chain/height
    // pub fn get_or_create_key(
    //     &mut self,
    //     chain_id: &[u8],
    //     height: u64,
    // ) -> Result<BIP340PubKey, &'static str> {
    //     // Check if key exists for this context
    //     if let Some(pubkey) = self.store.keys.get(&(chain_id.to_vec(), height)) {
    //         return Ok(*pubkey);
    //     }
    //
    //     // let mut rng = ChaCha20Rng::from_os_rng();
    //     // let signing_key = SigningKey::random(&mut rng);
    //
    //     // Generate new key pair
    //     let signing_key = SigningKey::random(&mut OsRng);
    //     // let verifying_key = signing_key.verifying_key();
    //     // let x_bytes = verifying_key.to_bytes();
    //     let bip340_pubkey = signing_key.verifying_key().to_bytes().into();
    //
    //     // Convert to BIP-340 x-only format
    //     // let bip340_pubkey = x_bytes.as_slice().try_into().unwrap();
    //
    //     // Store with context
    //     self.store
    //         .keys
    //         .insert((chain_id.to_vec(), height), bip340_pubkey);
    //
    //     self.store.key_pairs.insert(bip340_pubkey, signing_key);
    //
    //     Ok(bip340_pubkey)
    // }

    // GenerateRandomness generates a random scalar with the given key and src
    // the result is deterministic with each given input
    // pub fn generate_randomness(
    //     key: &[u8],
    //     chain_id: &[u8],
    //     height: u64,
    // ) -> (PrivateRand, PublicRand) {
    //     let mut iteration: u64 = 0;
    //
    //     loop {
    //         // calculate the random hash with iteration count
    //         let mut mac = HmacSha256::new_from_slice(key)
    //             .expect("HMAC can take key of any size");
    //
    //         // Append height as big-endian bytes
    //         let height_bytes = height.to_be_bytes();
    //         mac.update(&height_bytes);
    //
    //         // Append chain_id
    //         mac.update(chain_id);
    //
    //         // Append iteration as big-endian bytes
    //         let iteration_bytes = iteration.to_be_bytes();
    //         mac.update(&iteration_bytes);
    //
    //         // Get the digest
    //         let rand_pre = mac.finalize().into_bytes();
    //
    //         // Try to create a scalar from the bytes
    //         if let Some(scalar) = Scalar::from_repr_vartime(rand_pre.into()) {
    //             // Check if the scalar is zero
    //             if !scalar.is_zero().into() {
    //                 // Convert to private key
    //                 let priv_rand = scalar;
    //
    //                 // Compute public key
    //                 let point = ProjectivePoint::GENERATOR * priv_rand;
    //                 let affine = point.to_affine();
    //                 let pub_rand = affine.x();
    //
    //                 return (priv_rand, *pub_rand);
    //             }
    //         }
    //
    //         iteration += 1;
    //     }
    // }

    // Generate BIP-340 compliant randomness
    // pub fn generate_randomness2(
    //     privkey: &SigningKey,
    //     chain_id: &[u8],
    //     height: u64
    // ) -> Scalar {
    //     let mut hmac =
    //         HmacSha256::new_from_slice(privkey.to_bytes().as_slice()).expect("HMAC key valid");
    //
    //     hmac.update(chain_id);
    //     hmac.update(&height.to_be_bytes());
    //
    //     let seed = hmac.finalize().into_bytes();
    //     let mut rng = ChaCha20Rng::from_seed(seed.into());
    //
    //     loop {
    //         let mut bytes = [0u8; 32];
    //         rng.fill_bytes(&mut bytes);
    //
    //         if let Ok(scalar) = Scalar::try_from(&bytes.into()) {
    //             if !scalar.is_zero() {
    //                 return scalar;
    //             }
    //         }
    //     }
    // }

    //// Sign message with BIP-340 Schnorr signature
    // pub fn sign(
    //     &self,
    //     pubkey: &BIP340PubKey,
    //     msg: &[u8],
    //     chain_id: &[u8],
    //     height: u64,
    // ) -> Result<Signature, &'static str> {
    //     let signing_key = self.store.key_pairs.get(pubkey).ok_or("Key not found")?;
    //
    //     // Generate context-bound randomness
    //     let mut iteration = 0u64;
    //     let randomness = loop {
    //         let r = Self::generate_randomness(signing_key, chain_id, height, iteration);
    //         iteration += 1;
    //         if iteration > 100 {
    //             return Err("Rejection sampling failed");
    //         }
    //         if !r.is_zero() {
    //             break r;
    //         }
    //     };
    //
    //     let schnorr_key = SchnorrSigningKey::from(signing_key);
    //     // let mut rng = ChaCha20Rng::from_seed(randomness.to_bytes().into());
    //
    //     // Use StdRng instead of ChaCha20Rng
    //     let mut rng = StdRng::from_seed(randomness.to_bytes().into());
    //     // let mut rng = ChaCha20Rng::from_seed(randomness.to_bytes().into());
    //
    //     Ok(schnorr_key
    //         .sign_prehash_with_rng(&mut rng, msg)
    //         .map_err(|_| "Signing failed")?)
    // }
}

fn generate_randomness(privkey: &[u8], chain_id: &[u8], height: u64) -> (PrivateRand, BIP340PubKey) {
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
                let public_rand = PublicKey::from_secret_scalar(scalar_non_zero);
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
        assert!(!bool::from(priv_rand.is_zero()), "Private randomness should not be zero");

        // Check that public randomness is 32 bytes long
        assert_eq!(pub_rand.len(), 32, "Public randomness should be 32 bytes long");

        // Check that generating randomness twice with the same inputs produces the same result
        let (priv_rand2, pub_rand2) = generate_randomness(&privkey, &chain_id, height);
        assert_eq!(priv_rand, priv_rand2, "Private randomness should be deterministic");
        assert_eq!(pub_rand, pub_rand2, "Public randomness should be deterministic");

        // Check that different inputs produce different results
        let (priv_rand3, pub_rand3) = generate_randomness(&privkey, &chain_id, height + 1);
        assert_ne!(priv_rand, priv_rand3, "Different inputs should produce different private randomness");
        assert_ne!(pub_rand, pub_rand3, "Different inputs should produce different public randomness");

        // Verify that the public key is on the curve
        // let point = ProjectivePoint::from_bytes(&pub_rand);
        // assert!(bool::from(point.is_some()), "Public randomness should represent a valid curve point");
    }
}