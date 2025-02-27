use babylon_merkle::{
    Proof,
    hash::{inner_hash_opt, leaf_hash_opt},
    error::MerkleError,
    tree::hash_from_byte_slices,
    hash::empty_hash
};
use cosmwasm_std::Binary;
use sha2::{Digest, Sha256};

/// Generate a proof for the root of the Merkle tree
pub fn create_root_proof(root_hash: Vec<u8>, items: Vec<Vec<u8>>) -> Proof {
    let aunts = if items.len() <= 1 {
        Vec::new()
    } else {
        let k = get_split_point(items.len() as u64).unwrap() as usize;
        let left_hash = hash_from_byte_slices(items[..k].to_vec());
        let right_hash = hash_from_byte_slices(items[k..].to_vec());

        vec![left_hash, right_hash]
    };

    Proof {
        total: items.len() as u64,
        index: 0,
        leaf_hash: Binary::new(root_hash),
        aunts: aunts.into_iter().map(Binary::new).collect(),
    }
}


/// Generate a Merkle proof for an item at a specific index
pub fn generate_proof(items: Vec<Vec<u8>>, index: usize) -> Proof {
    if index >= items.len() {
        panic!("Index out of bounds");
    }

    let total = items.len();
    let leaf_hash = leaf_hash_opt(&mut Sha256::new(), &items[index]);
    let aunts = collect_proof_aunts(&mut Sha256::new(), &items, index);

    Proof {
        total: total as u64,
        index: index as u64,
        leaf_hash: Binary::new(leaf_hash),
        aunts: aunts.into_iter().map(Binary::new).collect(),
    }
}

fn hash_from_byte_slices_internal(sha: &mut Sha256, items: Vec<Vec<u8>>) -> Vec<u8> {
    match items.len() {
        0 => empty_hash(),
        1 => leaf_hash_opt(sha, &items[0]),
        _ => {
            let k = get_split_point(items.len() as u64).unwrap() as usize;
            let left = hash_from_byte_slices_internal(sha, items[..k].to_vec());
            let right = hash_from_byte_slices_internal(sha, items[k..].to_vec());
            inner_hash_opt(sha, &left, &right)
        }
    }
}

/// Extension function that computes both the root hash and a proof for a specific index
pub fn hash_and_proof_from_byte_slices(items: Vec<Vec<u8>>, proof_index: usize) -> (Vec<u8>, Proof) {
    if proof_index >= items.len() {
        panic!("Proof index out of bounds");
    }

    let mut aunts = Vec::new();
    let root_hash = hash_with_proof_internal(&mut Sha256::new(), &items, proof_index, &mut aunts);

    let proof = Proof {
        total: items.len() as u64,
        index: proof_index as u64,
        leaf_hash: Binary::new(leaf_hash_opt(&mut Sha256::new(), &items[proof_index])),
        aunts: aunts.into_iter().map(Binary::new).collect(),
    };

    (root_hash, proof)
}

/// Internal function that computes a hash while collecting proof aunts
fn hash_with_proof_internal(sha: &mut Sha256, items: &[Vec<u8>], proof_index: usize, aunts: &mut Vec<Vec<u8>>) -> Vec<u8> {
    match items.len() {
        0 => empty_hash(),
        1 => leaf_hash_opt(sha, &items[0]),
        _ => {
            let k = get_split_point(items.len() as u64).unwrap() as usize;

            if proof_index < k {
                // Proof index is in the left subtree
                let right_hash = hash_from_byte_slices(items[k..].to_vec());
                aunts.push(right_hash.clone());

                let left_hash = hash_with_proof_internal(sha, &items[..k], proof_index, aunts);

                inner_hash_opt(sha, &left_hash, &right_hash)
            } else {
                // Proof index is in the right subtree
                let left_hash = hash_from_byte_slices(items[..k].to_vec());
                aunts.push(left_hash.clone());

                let right_hash = hash_with_proof_internal(sha, &items[k..], proof_index - k, aunts);

                inner_hash_opt(sha, &left_hash, &right_hash)
            }
        }
    }
}

/// Collect the proof aunts (hashes needed for verification) for an item at a specific index
fn collect_proof_aunts(sha: &mut Sha256, items: &[Vec<u8>], index: usize) -> Vec<Vec<u8>> {
    let mut aunts = Vec::new();
    collect_proof_aunts_recursive(sha, items, index, &mut aunts);
    aunts
}

fn collect_proof_aunts_recursive(sha: &mut Sha256, items: &[Vec<u8>], index: usize, aunts: &mut Vec<Vec<u8>>) {
    match items.len() {
        0 | 1 => {}, // Base case: no aunts to collect
        _ => {
            let k = get_split_point(items.len() as u64).unwrap() as usize;

            if index < k {
                // Target index is in the left subtree
                // Add the right subtree's hash as an aunt
                let right_hash = hash_from_byte_slices(items[k..].to_vec());
                aunts.push(right_hash);

                // Recurse into the left subtree
                collect_proof_aunts_recursive(sha, &items[..k], index, aunts);
            } else {
                // Target index is in the right subtree
                // Add the left subtree's hash as an aunt
                let left_hash = hash_from_byte_slices(items[..k].to_vec());
                aunts.push(left_hash);

                // Recurse into the right subtree with adjusted index
                collect_proof_aunts_recursive(sha, &items[k..], index - k, aunts);
            }
        }
    }
}

/// Verify a Merkle proof
pub fn verify_proof(proof: &Proof, root_hash: &[u8], item: &[u8]) -> bool {
    // First check if the leaf hash matches the item
    let computed_leaf_hash = leaf_hash_opt(&mut Sha256::new(), item);
    if computed_leaf_hash != proof.leaf_hash {
        return false;
    }

    // Compute the root hash from the proof
    let computed_root = compute_root_from_proof(proof, &computed_leaf_hash);

    // Compare with the expected root hash
    computed_root == root_hash
}

/// Compute the root hash from a proof
fn compute_root_from_proof(proof: &Proof, leaf_hash: &[u8]) -> Vec<u8> {
    let mut index = proof.index;
    let mut hash = leaf_hash.to_vec();

    for aunt in &proof.aunts {
        hash = if index % 2 == 0 {
            // Current hash is left sibling
            inner_hash_opt(&mut Sha256::new(), &hash, aunt)
        } else {
            // Current hash is right sibling
            inner_hash_opt(&mut Sha256::new(), aunt, &hash)
        };

        // Move up one level in the tree
        index /= 2;
    }

    hash
}

/// `get_split_point` returns the largest power of 2 less than length (reusing the provided function)
pub(crate) fn get_split_point(length: u64) -> Result<u64, MerkleError> {
    if length < 1 {
        return Err(MerkleError::generic_err(
            "Trying to split a tree with size < 1",
        ));
    }
    let u_length = length as usize;
    let bit_len = u_length.next_power_of_two().trailing_zeros();
    let k = 1 << bit_len.saturating_sub(1);
    if k == length {
        Ok(k >> 1)
    } else {
        Ok(k)
    }
}