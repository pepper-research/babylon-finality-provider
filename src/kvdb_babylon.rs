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
    use kvdb_memorydb::InMemory;
    use std::str::FromStr;
    const TEST_CHAIN_ID: &[u8] = b"test-chain";
    const TEST_PUBKEY: &[u8] = b"test-pubkey";

    fn setup_store() -> PubRandProofStore<InMemory> {  // Directly use InMemory type
        let db = kvdb_memorydb::create(1);  // Create raw InMemory instance
        PubRandProofStore::new(Arc::new(db))  // Arc-wrap here
    }

    #[test]
    fn test_composite_key() {
        let chain_id = b"test_chain";
        let fp_pubkey = b"test_pubkey";
        let height = 12345;

        let key = composite_key(chain_id, fp_pubkey, height);

        let mut expected = BytesMut::with_capacity(chain_id.len() + fp_pubkey.len() + 8);
        expected.put_slice(chain_id);
        expected.put_slice(fp_pubkey);
        expected.put_u64(height);

        assert_eq!(key, expected.to_vec());
    }

    // #[test]
    // fn test_pub_rand_proof_store() {
    //     let db = Arc::new(InMemory::default());
    //     let store = PubRandProofStore::new(db);
    //
    //     let chain_id = b"test_chain";
    //     let fp_pubkey = b"test_pubkey";
    //     let height = 12345;
    //
    //     let proof = Proof {
    //         index: 0,
    //         total: 0,
    //         leaf_hash: Default::default(),
    //         aunts: Default::default(),
    //     };
    //
    //     store
    //         .add_proofs(chain_id, fp_pubkey, height, &[proof.clone()])
    //         .unwrap();
    //
    //     let stored_proof = store.get_proof(chain_id, fp_pubkey, height).unwrap();
    //     assert_eq!(stored_proof, proof);
    // }
}