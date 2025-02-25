use anyhow::{anyhow, Context, Result};
use babylon_merkle::Proof;
use bincode;
use bytes::{BufMut, BytesMut};
use cosmwasm_schema::serde::Serialize;
use kvdb::{DBTransaction, KeyValueDB};
use std::sync::Arc;

const PROOF_COLUMN: u32 = 0;

pub struct PubRandProofStore<DB>
where
    DB: KeyValueDB + 'static,
{
    db: Arc<DB>,
}

impl<DB> PubRandProofStore<DB>
where
    DB: KeyValueDB,
{
    pub fn new(db: Arc<DB>) -> Self {
        Self { db }
    }

    pub fn add_proofs(
        &self,
        chain_id: &[u8],
        fp_pubkey: &[u8],
        start_height: u64,
        proofs: &[Proof],
    ) -> Result<()> {
        let mut tx = DBTransaction::new();

        proofs
            .iter()
            .enumerate()
            .try_for_each(|(i, proof)| -> Result<()> {
                let height = start_height + i as u64;
                let key = composite_key(chain_id, fp_pubkey, height);

                bincode::serialize(proof)
                    .map_err(|e| anyhow!("Serialization failed: {}", e))
                    .map(|proof_bytes| tx.put_vec(PROOF_COLUMN, key.as_slice(), proof_bytes))?;

                Ok(())
            })?;

        self.db
            .write(tx)
            .context("Failed to commit proofs to database")
    }

    pub fn get_proof(&self, chain_id: &[u8], fp_pubkey: &[u8], height: u64) -> Result<Proof> {
        let key = composite_key(chain_id, fp_pubkey, height);

        let proof_bytes = self
            .db
            .get(PROOF_COLUMN, &key)
            .context("Database read operation failed")?
            .ok_or_else(|| anyhow!("No proof found for height {}", height))?;

        bincode::deserialize(&proof_bytes).context("Failed to deserialize stored proof")
    }
}

// Composite key generation matching Go's getKey()
fn composite_key(chain_id: &[u8], fp_pubkey: &[u8], height: u64) -> Vec<u8> {
    let mut key = BytesMut::with_capacity(chain_id.len() + fp_pubkey.len() + 8);
    key.put_slice(chain_id);
    key.put_slice(fp_pubkey);
    key.put_u64(height);
    key.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::sha2::Digest;
    use kvdb_memorydb::InMemory;

    const TEST_CHAIN_ID: &[u8] = b"test-chain";
    const TEST_PUBKEY: &[u8] = b"test-pubkey";

    fn setup_store() -> PubRandProofStore<InMemory> {
        // Directly use InMemory type
        let db = kvdb_memorydb::create(1); // Create raw InMemory instance
        PubRandProofStore::new(Arc::new(db)) // Arc-wrap here
    }

    #[test]
    fn test_composite_key() {
        let height = 12345;

        let key = composite_key(TEST_CHAIN_ID, TEST_PUBKEY, height);

        let mut expected = BytesMut::with_capacity(TEST_CHAIN_ID.len() + TEST_PUBKEY.len() + 8);
        expected.put_slice(TEST_CHAIN_ID);
        expected.put_slice(TEST_PUBKEY);
        expected.put_u64(height);

        assert_eq!(key, expected.to_vec());
    }

    #[test]
    fn test_pub_rand_proof_store() {
        let store = setup_store();
        let height = 12345;

        let proof = Proof {
            index: 0,
            total: 0,
            leaf_hash: Default::default(),
            aunts: Default::default(),
        };

        store
            .add_proofs(TEST_CHAIN_ID, TEST_PUBKEY, height, &[proof.clone()])
            .unwrap();

        let stored_proof = store.get_proof(TEST_CHAIN_ID, TEST_PUBKEY, height).unwrap();
        assert_eq!(stored_proof, proof);
    }

    #[test]
    fn test_store_retrieve_single_proof() -> Result<()> {
        let store = setup_store();

        let leaf = b"foo";
        let leaf_hash = babylon_merkle::hash::leaf_hash(leaf);

        let proof = Proof {
            total: 1,
            index: 0,
            leaf_hash: leaf_hash.clone().into(),
            aunts: vec![vec![0; 32].into()],
        };

        store.add_proofs(TEST_CHAIN_ID, TEST_PUBKEY, 100, &[proof.clone()])?;
        let retrieved = store.get_proof(TEST_CHAIN_ID, TEST_PUBKEY, 100)?;

        assert_eq!(retrieved, proof);
        Ok(())
    }

    #[test]
    fn test_missing_proof() {
        let store = setup_store();
        let result = store.get_proof(TEST_CHAIN_ID, TEST_PUBKEY, 100);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No proof found"));
    }

    #[test]
    fn test_proof_overwrite() -> Result<()> {
        let store = setup_store();

        let leaf1 = b"foo1";
        let leaf_hash1 = babylon_merkle::hash::leaf_hash(leaf1);

        let leaf2 = b"foo2";
        let leaf_hash2 = babylon_merkle::hash::leaf_hash(leaf2);

        let proof1 = Proof {
            total: 1,
            index: 0,
            leaf_hash: leaf_hash1.clone().into(),
            aunts: vec![vec![0; 32].into()],
        };

        let proof2 = Proof {
            total: 1,
            index: 0,
            leaf_hash: leaf_hash2.clone().into(),
            aunts: vec![vec![0; 32].into()],
        };

        store.add_proofs(TEST_CHAIN_ID, TEST_PUBKEY, 200, &[proof1.clone()])?;
        store.add_proofs(TEST_CHAIN_ID, TEST_PUBKEY, 200, &[proof2.clone()])?;

        let retrieved = store.get_proof(TEST_CHAIN_ID, TEST_PUBKEY, 200)?;
        assert_eq!(retrieved, proof2);
        Ok(())
    }

    #[test]
    fn test_multiple_proofs() -> Result<()> {
        let store = setup_store();

        let leaf1 = b"foo1";
        let leaf_hash1 = babylon_merkle::hash::leaf_hash(leaf1);

        let leaf2 = b"foo2";
        let leaf_hash2 = babylon_merkle::hash::leaf_hash(leaf2);

        let proof1 = Proof {
            total: 1,
            index: 0,
            leaf_hash: leaf_hash1.clone().into(),
            aunts: vec![vec![0; 32].into()],
        };

        let proof2 = Proof {
            total: 1,
            index: 0,
            leaf_hash: leaf_hash2.clone().into(),
            aunts: vec![vec![0; 32].into()],
        };

        let proofs = vec![proof1, proof2];

        store.add_proofs(TEST_CHAIN_ID, TEST_PUBKEY, 300, &proofs)?;

        for (i, expected) in proofs.iter().enumerate() {
            let height = 300 + i as u64;
            let retrieved = store.get_proof(TEST_CHAIN_ID, TEST_PUBKEY, height)?;
            assert_eq!(&retrieved, expected);
        }
        Ok(())
    }
}
