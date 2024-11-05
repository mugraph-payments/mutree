#![allow(clippy::doc_lazy_continuation)]

use std::marker::PhantomData;

use digest::Digest;
use proptest::prelude::*;

use crate::prelude::*;

mod neighbor;
mod proof;
mod step;

pub use self::{neighbor::Neighbor, proof::Proof, step::Step};

pub struct Forestry<D: Digest> {
    pub proof: Proof,
    pub root: Hash,
    _phantom: PhantomData<D>,
}

impl<D: Digest> Forestry<D> {
    /// Constructs a new Forestry from its proof.
    #[inline]
    pub fn from_proof(proof: Proof) -> Self {
        let root = Self::calculate_root(&proof);
        Self {
            proof,
            root,
            _phantom: PhantomData,
        }
    }

    #[inline]
    pub fn from_root(root: &[u8]) -> Result<Self> {
        if root.len() != 32 {
            return Err(Error::InvalidLength);
        }

        Ok(Self {
            proof: Proof::new(),
            root: Hash::from_slice(root),
            _phantom: PhantomData,
        })
    }

    /// Constructs a new empty Forestry.
    #[inline]
    pub fn empty() -> Self {
        Self {
            proof: Proof::new(),
            root: Hash::zero(),
            _phantom: PhantomData,
        }
    }

    /// Checks if the Forestry is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.proof.is_empty()
    }

    /// Verifies if an element is present in the trie with a specific value.
    #[inline]
    pub fn verify(&self, key: &[u8], value: &[u8]) -> bool {
        if self.is_empty() {
            return false;
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = Hash::digest::<D>(value);

        // Verify the proof contains the exact key-value pair
        let contains_pair = self.proof.iter().any(|step| {
            matches!(step, Step::Leaf { key: leaf_key, value: leaf_value, .. }
                if *leaf_key == key_hash && *leaf_value == value_hash)
        });

        // Verify the root hash matches
        let calculated_root = Self::calculate_root(&self.proof);
        contains_pair && calculated_root == self.root
    }

    /// Inserts an element to the trie.
    #[inline]
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<Hash, Error> {
        if key.is_empty() {
            return Err(Error::EmptyKeyOrValue);
        }

        let key_hash = Hash::digest::<D>(key);
        let value_hash = Hash::digest::<D>(value);

        self.proof = self.insert_to_proof(key_hash, value_hash);
        self.root = Self::calculate_root(&self.proof);

        Ok(value_hash)
    }

    /// Verifies a proof for a given key and value.
    #[inline]
    pub fn verify_proof(&self, key: Hash, value: Hash, proof: &Proof) -> bool {
        if proof.is_empty() {
            return false;
        }

        proof.iter().any(|step| {
            matches!(step, Step::Leaf { key: leaf_key, value: leaf_value, .. } if *leaf_key == key && *leaf_value == value)
        })
    }

    /// Inserts a key-value pair into the proof.
    fn insert_to_proof(&self, key: Hash, value: Hash) -> Proof {
        let mut new_proof = self.proof.clone();
        // Remove any existing leaf with the same key
        new_proof
            .retain(|step| !matches!(step, Step::Leaf { key: leaf_key, .. } if *leaf_key == key));
        new_proof.push(Step::Leaf {
            skip: 0,
            key,
            value,
        });
        Self::compress_path(&mut new_proof);
        new_proof
    }

    /// Applies path compression to the proof.
    fn compress_path(proof: &mut Proof) {
        let mut i = 0;
        while i < proof.len() - 1 {
            if let (
                Step::Branch {
                    skip: skip1,
                    neighbors: neighbors1,
                },
                Step::Branch {
                    skip: skip2,
                    neighbors: neighbors2,
                },
            ) = (&proof[i], &proof[i + 1])
            {
                if neighbors1.iter().filter(|&&n| n != Hash::zero()).count() == 1
                    && neighbors2.iter().filter(|&&n| n != Hash::zero()).count() == 1
                {
                    // Merge the two branch nodes
                    let new_skip = skip1 + skip2 + 1;
                    let new_neighbors = *neighbors2;
                    proof[i] = Step::Branch {
                        skip: new_skip,
                        neighbors: new_neighbors,
                    };
                    proof.remove(i + 1);
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
    }

    /// Calculates the root hash of the Merkle Patricia Forestry.
    fn calculate_root(proof: &Proof) -> Hash {
        let mut hasher = D::new();
        for step in proof.iter() {
            match step {
                Step::Branch { neighbors, .. } => {
                    // First hash the number of non-zero neighbors
                    let non_zero = neighbors.iter().filter(|&&n| n != Hash::zero()).count();
                    hasher.update([non_zero as u8]);
                    // Then hash each non-zero neighbor in order
                    for neighbor in neighbors.iter().filter(|&&n| n != Hash::zero()) {
                        hasher.update(neighbor.as_ref());
                    }
                }
                Step::Fork { neighbor, .. } => {
                    // Hash fork marker
                    hasher.update([0xFF]);
                    // Hash nibble and prefix
                    hasher.update([neighbor.nibble]);
                    hasher.update(&neighbor.prefix);
                    // Hash root
                    hasher.update(neighbor.root.as_ref());
                }
                Step::Leaf { key, value, .. } => {
                    // Hash leaf marker
                    hasher.update([0x00]);
                    // Hash key and value
                    hasher.update(key.as_ref());
                    hasher.update(value.as_ref());
                }
            }
        }
        Hash::from_slice(hasher.finalize().as_ref())
    }
}

impl<D: Digest> Clone for Forestry<D> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            root: self.root,
            _phantom: PhantomData,
        }
    }
}

impl<D: Digest> PartialEq for Forestry<D> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}

impl<D: Digest> Eq for Forestry<D> {}

impl<D: Digest> std::fmt::Debug for Forestry<D> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forestry")
            .field("proof", &self.proof)
            .field("root", &self.root)
            .finish()
    }
}

impl<D: Digest> Default for Forestry<D> {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

impl<D: Digest + 'static> Arbitrary for Forestry<D> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    #[inline]
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<Proof>()
            .prop_map(|proof| Self::from_proof(proof))
            .boxed()
    }
}

impl<D: Digest + 'static> CvRDT for Forestry<D> {
    #[inline]
    fn merge(&mut self, other: &Self) -> Result<()> {
        let mut merged_proof = self.proof.clone();
        for step in other.proof.iter() {
            if !merged_proof.contains(step) {
                merged_proof.push(step.clone());
            }
        }

        self.proof = merged_proof;
        self.root = Self::calculate_root(&self.proof);

        Ok(())
    }
}

impl<D: Digest + 'static> CmRDT<Proof> for Forestry<D> {
    #[inline]
    fn apply(&mut self, op: &Proof) -> Result<()> {
        let mpf = Self::from_proof(op.clone());
        self.merge(&mpf)
    }
}

#[cfg(all(test, any(feature = "blake3", feature = "sha2")))]
mod tests {
    use std::cmp::Ordering;

    use digest::consts::U32;
    use test_strategy::proptest;

    use super::*;

    macro_rules! generate_mpf_tests {
        ($digest:ty) => {
            paste::paste! {
                mod [<$digest:snake _tests>] {
                    use super::*;
                    use $digest;
                    use proptest::collection::vec;
                    use ::test_strategy::proptest;

                    type ForestryT = Forestry<$digest>;
                    $crate::test_state_crdt_properties!(ForestryT);

                    fn non_empty_string() -> impl Strategy<Value = String> {
                        any::<String>().prop_filter("must not be empty", |s| !s.is_empty())
                    }

                    #[proptest]
                    fn test_verify_proof(
                        mut trie: Forestry<$digest>,
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        trie.insert(key.as_bytes(), value.as_bytes())?;
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()),
                            "Proof verification failed for key: {:?}, value: {:?}",
                            key, value);
                    }

                    #[proptest]
                    fn test_insert(
                        mut trie: Forestry<$digest>,
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        let original_trie = trie.clone();
                        trie.insert(key.as_bytes(), value.as_bytes())?;
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()));
                        prop_assert_ne!(trie, original_trie);
                    }

                    #[proptest]
                    fn test_multiple_inserts(
                        mut trie: Forestry<$digest>,
                        #[strategy(non_empty_string())] key1: String,
                        value1: String,
                        #[strategy(non_empty_string())] key2: String,
                        value2: String
                    ) {
                        prop_assume!(key1 != key2);

                        let original_trie = trie.clone();
                        trie.insert(key1.as_bytes(), value1.as_bytes())?;
                        prop_assert!(trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert_ne!(&trie, &original_trie);

                        let trie_after_first_insert = trie.clone();
                        trie.insert(key2.as_bytes(), value2.as_bytes())?;
                        prop_assert!(trie.verify(key2.as_bytes(), value2.as_bytes()));
                        prop_assert_ne!(&trie, &trie_after_first_insert);

                        prop_assert!(trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(trie.verify(key2.as_bytes(), value2.as_bytes()));
                    }

                    #[test]
                    fn test_empty_trie() {
                        let empty_trie = Forestry::<$digest>::empty();
                        assert!(empty_trie.is_empty());
                    }

                    #[proptest]
                    fn test_start_empty_add_one_check_hash(
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        let mut trie = Forestry::<$digest>::empty();
                        assert!(trie.is_empty());

                        let empty_root = trie.root;
                        trie.insert(key.as_bytes(), value.as_bytes())?;
                        prop_assert!(!trie.is_empty());
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()));

                        prop_assert_ne!(empty_root, trie.root, "Hash should change after insertion");
                    }

                    #[proptest]
                    fn test_proof_verification(
                        #[strategy(non_empty_string())] key1: String,
                        value1: String,
                        #[strategy(non_empty_string())] key2: String,
                        value2: String
                    ) {
                        prop_assume!(key1 != key2);
                        prop_assume!(value1 != value2);

                        // Test empty trie
                        let empty_trie = Forestry::<$digest>::empty();
                        prop_assert!(!empty_trie.verify(key1.as_bytes(), value1.as_bytes()));

                        // Test non-empty trie
                        let mut non_empty_trie = Forestry::<$digest>::empty();
                        non_empty_trie.insert(key1.as_bytes(), value1.as_bytes())?;

                        prop_assert!(non_empty_trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(!non_empty_trie.verify(key2.as_bytes(), value1.as_bytes()));
                        prop_assert!(!non_empty_trie.verify(key1.as_bytes(), value2.as_bytes()));
                        prop_assert!(!non_empty_trie.verify(key2.as_bytes(), value2.as_bytes()));

                        // Test updating an existing key
                        non_empty_trie.insert(key1.as_bytes(), value2.as_bytes())?;
                        prop_assert!(!non_empty_trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(non_empty_trie.verify(key1.as_bytes(), value2.as_bytes()));
                    }


                    #[proptest]
                    fn test_proof_size(
                        trie: Forestry<$digest>,
                    ) {
                        let proof = trie.proof.clone();
                        prop_assert!(proof.len() <= 130 * (4 + 1),
                            "Proof size {} exceeds expected maximum",
                            proof.len());
                    }

                    #[test]
                    fn test_empty_key_or_value() {
                        let mut trie = Forestry::<$digest>::empty();
                        assert!(matches!(trie.insert(&[], b"value"), Err(Error::EmptyKeyOrValue)));
                        assert!(trie.insert(b"key", &[]).is_ok());
                    }

                    #[proptest]
                    fn test_root_proof_equality(
                        #[strategy(any::<Forestry<$digest>>())] trie1: Forestry<$digest>,
                        #[strategy(any::<Forestry<$digest>>())] trie2: Forestry<$digest>
                    ) {
                        prop_assert_eq!(
                            trie1.root == trie2.root,
                            trie1.proof == trie2.proof,
                            "Root equality should imply proof equality"
                        );
                    }

                    #[proptest]
                    fn test_default_is_empty(
                        #[strategy(Just(Forestry::<$digest>::default()))] default_trie: Forestry<$digest>
                    ) {
                        prop_assert!(default_trie.is_empty(), "Default instance should be empty");
                    }

                    #[proptest]
                    fn test_root_matches_calculated(
                        #[strategy(any::<Forestry<$digest>>())] trie: Forestry<$digest>
                    ) {
                        let calculated_root = Forestry::<$digest>::calculate_root(&trie.proof);
                        prop_assert_eq!(trie.root, calculated_root, "Root should match calculated root");
                    }

                    #[proptest]
                    fn test_from_proof_root_calculation(#[strategy(any::<Proof>())] proof: Proof) {
                        let trie = Forestry::<$digest>::from_proof(proof.clone());
                        let calculated_root = Forestry::<$digest>::calculate_root(&proof);
                        prop_assert_eq!(trie.root, calculated_root, "Root should match calculated root after from_proof");
                    }

                    #[proptest]
                    fn test_verify_non_existent(
                        #[strategy(any::<Forestry<$digest>>())] mut trie: Forestry<$digest>,
                        #[strategy(non_empty_string())] key1: String,
                        value1: String,
                        #[strategy(non_empty_string())] key2: String,
                        value2: String
                    ) {
                        prop_assume!(key1 != key2);
                        prop_assume!(value1 != value2);

                        trie.insert(key1.as_bytes(), value1.as_bytes())?;

                        // Verify correct key-value pair
                        prop_assert!(trie.verify(key1.as_bytes(), value1.as_bytes()));

                        // Verify non-existent key
                        prop_assert!(!trie.verify(key2.as_bytes(), value1.as_bytes()));

                        // Verify existing key with wrong value
                        prop_assert!(!trie.verify(key1.as_bytes(), value2.as_bytes()));

                        // Verify non-existent key-value pair
                        prop_assert!(!trie.verify(key2.as_bytes(), value2.as_bytes()));
                    }


                    #[proptest]
                    fn test_second_preimage_resistance(
                        mut trie: Forestry<$digest>,
                        #[strategy(vec(any::<u8>(), 1..100))] key1: Vec<u8>,
                        #[strategy(vec(any::<u8>(), 1..100))] key2: Vec<u8>,
                        value1: u8,
                        value2: u8
                    ) {
                        prop_assume!(key1 != key2);

                        trie.insert(&key1, &[value1])?;
                        let root1 = trie.root;

                        trie.insert(&key2, &[value2])?;
                        let root2 = trie.root;

                        prop_assert_ne!(root1, root2, "Different key-value pairs should produce different trie states");

                        // Verify both key-value pairs are present
                        prop_assert!(trie.verify(&key1, &[value1]), "First key-value pair not found");
                        prop_assert!(trie.verify(&key2, &[value2]), "Second key-value pair not found");
                    }

                    #[proptest]
                    fn test_malicious_proof_resistance(
                        trie: Forestry<$digest>,
                        key: Vec<u8>,
                        value: u8,
                        malicious_steps: Vec<Step>
                    ) {
                        // Skip the test if the trie is empty and there are no malicious steps
                        prop_assume!(!trie.is_empty() || !malicious_steps.is_empty());

                        let mut malicious_proof = trie.proof.clone();
                        malicious_proof.extend(malicious_steps);

                        let malicious_trie = Forestry::<$digest>::from_proof(malicious_proof);

                        // Verify that the malicious trie doesn't falsely claim to contain the key-value pair
                        prop_assert!(!malicious_trie.verify(&key, &[value]), "Malicious proof falsely verified");

                        // Ensure the root hash of the malicious trie is different
                        prop_assert_ne!(trie.root, malicious_trie.root, "Malicious trie has the same root hash");
                    }

                    #[proptest]
                    fn test_large_key_value_pairs(
                        mut trie: Forestry<$digest>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_key: Vec<u8>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_value: Vec<u8>
                    ) {
                        let initial_size = trie.proof.len();
                        trie.insert(&large_key, &large_value)?;
                        prop_assert!(trie.verify(&large_key, &large_value), "Failed to verify large key-value pair");

                        // Check that trie size increase is reasonable
                        let size_increase = trie.proof.len() - initial_size;
                        prop_assert!(size_increase <= large_key.len() + large_value.len(),
                            "Trie size increase {} is larger than key size {} plus value size {}",
                            size_increase, large_key.len(), large_value.len());
                    }

                    #[proptest]
                    fn test_path_compression(
                        mut trie: Forestry<$digest>,
                        #[strategy(non_empty_string())] key1: String,
                        #[strategy(non_empty_string())] key2: String,
                        value1: String,
                        value2: String,
                    ) {
                        prop_assume!(key1 != key2);

                        // Insert two elements that should trigger path compression
                        trie.insert(key1.as_bytes(), value1.as_bytes())?;
                        trie.insert(key2.as_bytes(), value2.as_bytes())?;

                        // Verify the proof length is optimal after compression
                        prop_assert!(
                            trie.proof.len() <= 5,
                            "Proof length exceeds expected maximum after compression"
                        );
                    }

                    type Mpf = Forestry<$digest>;
                    crate::test_state_crdt_properties!(Mpf);
                    crate::test_op_crdt_properties!(Mpf, Proof);
                }
            }
        };
    }

    type Blake2s = blake2::Blake2s256;
    generate_mpf_tests!(Blake2s);

    type Blake2b = blake2::Blake2b<U32>;
    generate_mpf_tests!(Blake2b);

    #[cfg(feature = "blake3")]
    type Blake3 = blake3::Hasher;
    #[cfg(feature = "blake3")]
    generate_mpf_tests!(Blake3);

    #[cfg(feature = "sha2")]
    type Sha2_256 = sha2::Sha256;
    #[cfg(feature = "sha2")]
    generate_mpf_tests!(Sha2_256);

    #[cfg(feature = "sha3")]
    type Sha3_256 = sha3::Sha3_256;
    #[cfg(feature = "sha3")]
    generate_mpf_tests!(Sha3_256);

    #[proptest]
    fn test_merkle_proof_reflexive(proof: Proof) {
        prop_assert_eq!(proof.partial_cmp(&proof), Some(Ordering::Equal));
    }

    #[proptest]
    fn test_merkle_proof_antisymmetric(proof1: Proof, proof2: Proof) {
        if proof1 == proof2 {
            prop_assert_eq!(proof1.partial_cmp(&proof2), Some(Ordering::Equal));
            prop_assert_eq!(proof2.partial_cmp(&proof1), Some(Ordering::Equal));
        } else if let (Some(ord1), Some(ord2)) =
            (proof1.partial_cmp(&proof2), proof2.partial_cmp(&proof1))
        {
            prop_assert_ne!(ord1, ord2);
        }
    }

    #[proptest]
    fn test_merkle_proof_transitive(proof1: Proof, proof2: Proof, proof3: Proof) {
        if let (Some(ord1), Some(ord2)) = (proof1.partial_cmp(&proof2), proof2.partial_cmp(&proof3)) {
            if ord1 == ord2 {
                prop_assert_eq!(proof1.partial_cmp(&proof3), Some(ord1));
            }
        }
    }

    #[proptest]
    fn test_merkle_proof_consistency(proof1: Proof, proof2: Proof) {
        let cmp1 = proof1.partial_cmp(&proof2);
        let cmp2 = proof2.partial_cmp(&proof1);

        match (cmp1, cmp2) {
            (Some(Ordering::Less), Some(Ordering::Greater))
            | (Some(Ordering::Greater), Some(Ordering::Less))
            | (Some(Ordering::Equal), Some(Ordering::Equal)) => {}
            (None, None) => {}
            _ => prop_assert!(false, "Inconsistent comparison: {:?} vs {:?}", cmp1, cmp2),
        }
    }
}
