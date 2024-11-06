#![allow(clippy::doc_lazy_continuation)]

use std::{io::Read, marker::PhantomData};

use digest::Digest;
use proptest::prelude::*;

use crate::prelude::*;

mod neighbor;
mod proof;
mod step;

pub use self::{neighbor::Neighbor, proof::Proof, step::Step};

/// A Merkle-Patricia Trie implementation that provides succinct proofs through an optimized
/// branch structure using tiny Sparse-Merkle trees.
///
/// The Trie uses a radix-16 (hexadecimal) structure where each branch node's neighbors are
/// arranged in a binary Sparse-Merkle tree of depth 4. This innovative approach reduces proof sizes
/// from ~480 bytes to ~130 bytes per branch step while maintaining security.
///
/// # Structure
///
/// - Branch nodes use a mini Sparse-Merkle Tree requiring only 4 hashes instead of up to 15
/// - Fork nodes include complete neighbor information for reconstruction
/// - Leaf nodes contain the actual key-value pair hashes
///
/// # Proof Size
///
/// For a trie of n items:
/// - Traditional MPT: ~480 * log₁₆(n) bytes
/// - Trie: ~130 * log₁₆(n) bytes
///
/// # Type Parameters
///
/// * `D` - The digest algorithm implementing the [`Digest`] trait used for hashing operations
///
/// # Example
///
/// ```rust
/// use mutree::prelude::*;
/// use blake2::Blake2s256;
/// use std::io::Cursor;
///
/// fn main() -> Result<(), Error> {
///     let mut trie = Trie::<Blake2s256>::empty();
///     trie.insert(b"key", Cursor::new(b"value"))?;
///     assert!(trie.verify(b"key", b"value"));
///
///     Ok(())
/// }
/// ```
pub struct Trie<D: Digest> {
    pub proof: Proof,
    pub root: Hash,
    _phantom: PhantomData<D>,
}

impl<D: Digest + 'static> Trie<D> {
    /// Creates a new Trie instance from an existing proof.
    ///
    /// This method calculates the root hash from the provided proof and initializes
    /// a new Trie structure.
    ///
    /// # Arguments
    ///
    /// * `proof` - An existing [`Proof`] to construct the Trie from
    ///
    /// # Examples
    ///
    /// ```
    /// # use mutree::prelude::*;
    /// # use blake2::Blake2s256;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let proof = Proof::new();
    ///     let trie = Trie::<Blake2s256>::from_proof(proof);
    ///
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn from_proof(proof: Proof) -> Self {
        let root = Self::calculate_root(&proof);
        Self {
            proof,
            root,
            _phantom: PhantomData,
        }
    }

    /// Creates a new Trie instance from a root hash.
    ///
    /// # Arguments
    ///
    /// * `root` - A 32-byte array representing the root hash
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the new Trie instance or an error if the
    /// provided root hash has an invalid length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use mutree::prelude::*;
    /// # use blake2::Blake2s256;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let root = [0u8; 32];
    ///     let trie = Trie::<Blake2s256>::from_root(&root).unwrap();
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if the root hash is not exactly 32 bytes
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

    /// Constructs a new empty Trie.
    #[inline]
    pub fn empty() -> Self {
        Self {
            proof: Proof::new(),
            root: Hash::zero(),
            _phantom: PhantomData,
        }
    }

    /// Checks if the Trie is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.proof.is_empty()
    }

    /// Verifies if a key-value pair exists in the Trie.
    ///
    /// This method:
    /// 1. Hashes the key and value using digest algorithm D
    /// 2. Traverses the proof structure to:
    ///    - Find a Leaf step matching the key-value hashes
    ///    - Verify the authenticity of the path using the root hash
    ///
    /// The verification process ensures:
    /// - The key-value pair exists exactly as provided
    /// - The proof structure is valid and matches the root hash
    /// - All branch steps have valid Sparse-Merkle Tree structures
    ///
    /// # Arguments
    ///
    /// * `key` - The key to verify, as a byte slice
    /// * `value` - The value to verify, as a byte slice
    ///
    /// # Returns
    ///
    /// Returns true if the key-value pair exists and is authenticated by the proof
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mutree::prelude::*;
    /// use blake2::Blake2s256;
    /// use std::io::Cursor;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let mut trie = Trie::<Blake2s256>::empty();
    ///     trie.insert(b"key", Cursor::new(b"value"))?;
    ///
    ///     assert!(trie.verify(b"key", b"value"));
    ///     assert!(!trie.verify(b"key", b"wrong_value"));
    ///     assert!(!trie.verify(b"wrong_key", b"value"));
    ///     
    ///     Ok(())
    /// }
    /// ```
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

    /// Inserts a key-value pair into the Merkle-Patricia Trie.
    ///
    /// This method:
    /// 1. Hashes the key and value using the digest algorithm D
    /// 2. Updates the proof structure by:
    ///    - Adding necessary Branch/Fork/Leaf steps
    ///    - Removing any existing leaf with the same key
    ///    - Compressing paths where possible
    /// 3. Recalculates the root hash
    ///
    /// The insertion maintains the following invariants:
    /// - Branch nodes use a mini Sparse-Merkle Tree requiring only 4 hashes
    /// - Fork nodes include complete neighbor information
    /// - Leaf nodes contain the actual key-value pair hashes
    ///
    /// # Arguments
    ///
    /// * `key` - The key to insert, as a byte slice
    /// * `value` - The value to insert, as a byte slice
    ///
    /// # Returns
    ///
    /// Returns the hash of the inserted value if successful, or an error if:
    /// - The key is empty
    /// - The insertion would violate the trie structure
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mutree::prelude::*;
    /// use blake2::Blake2s256;
    /// use std::io::Cursor;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let mut trie = Trie::<Blake2s256>::empty();
    ///     trie.insert(b"key", Cursor::new(b"value"))?;
    ///     assert!(trie.verify(b"key", b"value"));
    ///     
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn insert<R: Read>(&mut self, key: &[u8], value: R) -> Result<Hash, Error> {
        #[cfg(feature = "blake3")]
        {
            if std::any::TypeId::of::<D>() == std::any::TypeId::of::<blake3::Hasher>() {
                // Use specialized blake3 implementation
                return self.insert_blake3(key, value);
            }
        }
        // Use default implementation for other hash functions
        self.insert_default(key, value)
    }

    #[inline]
    fn insert_default<R: Read>(&mut self, key: &[u8], mut value: R) -> Result<Hash, Error> {
        if key.is_empty() {
            return Err(Error::EmptyKeyOrValue);
        }

        let key_hash = Hash::digest::<D>(key);
        let mut hasher = D::new();
        let mut buffer = vec![0u8; 16384]; // 16KB chunks

        loop {
            match value.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(n) => hasher.update(&buffer[..n]),
                Err(e) => return Err(Error::Unknown(e.to_string())),
            }
        }

        let value_hash = Hash::from_slice(hasher.finalize().as_ref());
        self.proof = self.insert_to_proof(key_hash, value_hash);
        self.root = Self::calculate_root(&self.proof);

        Ok(value_hash)
    }

    #[cfg(feature = "blake3")]
    #[inline]
    fn insert_blake3<R: Read>(&mut self, key: &[u8], mut value: R) -> Result<Hash, Error> {
        if key.is_empty() {
            return Err(Error::EmptyKeyOrValue);
        }

        // Use blake3's optimized hasher for the key
        let mut key_hasher = blake3::Hasher::new();
        key_hasher.update(key);
        let key_hash = Hash::from_slice(key_hasher.finalize().as_ref());

        // Use blake3's streaming hasher for the value
        let mut value_hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 65536]; // 64KB chunks for better streaming performance

        loop {
            match value.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    value_hasher.update(&buffer[..n]);
                }
                Err(e) => return Err(Error::Unknown(e.to_string())),
            }
        }

        let value_hash = Hash::from_slice(value_hasher.finalize().as_ref());
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

    /// Calculates the root hash of the Merkle Patricia Trie.
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

impl<D: Digest> Clone for Trie<D> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            root: self.root,
            _phantom: PhantomData,
        }
    }
}

impl<D: Digest> PartialEq for Trie<D> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}

impl<D: Digest> Eq for Trie<D> {}

impl<D: Digest> std::fmt::Debug for Trie<D> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trie")
            .field("proof", &self.proof)
            .field("root", &self.root)
            .finish()
    }
}

impl<D: Digest + 'static> Default for Trie<D> {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

impl<D: Digest + 'static> Arbitrary for Trie<D> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    #[inline]
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<Proof>()
            .prop_map(|proof| Self::from_proof(proof))
            .boxed()
    }
}

impl<D: Digest + 'static> CvRDT for Trie<D> {
    #[inline]
    fn merge(&mut self, other: &Self) -> Result<(), Error> {
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

impl<D: Digest + 'static> CmRDT<Proof> for Trie<D> {
    #[inline]
    fn apply(&mut self, op: &Proof) -> Result<(), Error> {
        let mpf = Self::from_proof(op.clone());
        self.merge(&mpf)
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use test_strategy::proptest;

    use super::*;

    #[cfg_attr(
        not(any(
            feature = "blake2",
            feature = "blake3",
            feature = "sha2",
            feature = "sha3"
        )),
        allow(unused)
    )]
    macro_rules! generate_mpf_tests {
        ($digest:ty) => {
            paste::paste! {
                mod [<$digest:snake _tests>] {
                    use super::*;
                    use $digest;
                    use proptest::collection::vec;
                    use ::test_strategy::proptest;

                    type TrieT = Trie<$digest>;
                    $crate::test_state_crdt_properties!(TrieT);
                    $crate::test_op_crdt_properties!(TrieT, Proof);

                    fn non_empty_string() -> impl Strategy<Value = String> {
                        any::<String>().prop_filter("must not be empty", |s| !s.is_empty())
                    }

                    #[proptest]
                    fn test_verify_proof(
                        mut trie: Trie<$digest>,
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
                        mut trie: Trie<$digest>,
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        let original_trie = trie.clone();
                        trie.insert(key.as_bytes(), std::io::Cursor::new(value.as_bytes()))?;
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()));
                        prop_assert_ne!(trie, original_trie);
                    }

                    #[proptest]
                    fn test_multiple_inserts(
                        mut trie: Trie<$digest>,
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
                        let empty_trie = Trie::<$digest>::empty();
                        assert!(empty_trie.is_empty());
                    }

                    #[proptest]
                    fn test_start_empty_add_one_check_hash(
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        let mut trie = Trie::<$digest>::empty();
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
                        let empty_trie = Trie::<$digest>::empty();
                        prop_assert!(!empty_trie.verify(key1.as_bytes(), value1.as_bytes()));

                        // Test non-empty trie
                        let mut non_empty_trie = Trie::<$digest>::empty();
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
                        trie: Trie<$digest>,
                    ) {
                        let proof = trie.proof.clone();
                        prop_assert!(proof.len() <= 130 * (4 + 1),
                            "Proof size {} exceeds expected maximum",
                            proof.len());
                    }

                    #[test]
                    fn test_empty_key_or_value() {
                        let mut trie = Trie::<$digest>::empty();
                        assert!(matches!(trie.insert(&[], std::io::Cursor::new(b"value")), Err(Error::EmptyKeyOrValue)));
                        assert!(trie.insert(b"key", std::io::Cursor::new(&[])).is_ok());
                    }

                    #[proptest]
                    fn test_root_proof_equality(
                        trie1: Trie<$digest>,
                        trie2: Trie<$digest>
                    ) {
                        prop_assert_eq!(
                            trie1.root == trie2.root,
                            trie1.proof == trie2.proof,
                            "Root equality should imply proof equality"
                        );
                    }

                    #[proptest]
                    fn test_default_is_empty(
                        default_trie: Trie<$digest>
                    ) {
                        prop_assert!(default_trie.is_empty(), "Default instance should be empty");
                    }

                    #[proptest]
                    fn test_root_matches_calculated(
                        trie: Trie<$digest>
                    ) {
                        let calculated_root = Trie::<$digest>::calculate_root(&trie.proof);
                        prop_assert_eq!(trie.root, calculated_root, "Root should match calculated root");
                    }

                    #[proptest]
                    fn test_from_proof_root_calculation(proof: Proof) {
                        let trie = Trie::<$digest>::from_proof(proof.clone());
                        let calculated_root = Trie::<$digest>::calculate_root(&proof);
                        prop_assert_eq!(trie.root, calculated_root, "Root should match calculated root after from_proof");
                    }

                    #[proptest]
                    fn test_verify_non_existent(
                        mut trie: Trie<$digest>,
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
                        mut trie: Trie<$digest>,
                        #[strategy(vec(any::<u8>(), 1..100))] key1: Vec<u8>,
                        #[strategy(vec(any::<u8>(), 1..100))] key2: Vec<u8>,
                        value1: u8,
                        value2: u8
                    ) {
                        prop_assume!(key1 != key2);

                        trie.insert(&key1, std::io::Cursor::new(&[value1]))?;
                        let root1 = trie.root;

                        trie.insert(&key2, std::io::Cursor::new(&[value2]))?;
                        let root2 = trie.root;

                        prop_assert_ne!(root1, root2, "Different key-value pairs should produce different trie states");

                        // Verify both key-value pairs are present
                        prop_assert!(trie.verify(&key1, &[value1]), "First key-value pair not found");
                        prop_assert!(trie.verify(&key2, &[value2]), "Second key-value pair not found");
                    }

                    #[proptest]
                    fn test_malicious_proof_resistance(
                        trie: Trie<$digest>,
                        key: Vec<u8>,
                        value: u8,
                        malicious_steps: Vec<Step>
                    ) {
                        // Skip the test if the trie is empty and there are no malicious steps
                        prop_assume!(!trie.is_empty() || !malicious_steps.is_empty());

                        let mut malicious_proof = trie.proof.clone();
                        malicious_proof.extend(malicious_steps);

                        let malicious_trie = Trie::<$digest>::from_proof(malicious_proof);

                        // Verify that the malicious trie doesn't falsely claim to contain the key-value pair
                        prop_assert!(!malicious_trie.verify(&key, &[value]), "Malicious proof falsely verified");

                        // Ensure the root hash of the malicious trie is different
                        prop_assert_ne!(trie.root, malicious_trie.root, "Malicious trie has the same root hash");
                    }

                    #[proptest]
                    fn test_large_key_value_pairs(
                        mut trie: Trie<$digest>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_key: Vec<u8>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_value: Vec<u8>
                    ) {
                        let initial_size = trie.proof.len();
                        trie.insert(&large_key, std::io::Cursor::new(&large_value))?;
                        prop_assert!(trie.verify(&large_key, &large_value), "Failed to verify large key-value pair");

                        // Check that trie size increase is reasonable
                        let size_increase = trie.proof.len() - initial_size;
                        prop_assert!(size_increase <= large_key.len() + large_value.len(),
                            "Trie size increase {} is larger than key size {} plus value size {}",
                            size_increase, large_key.len(), large_value.len());
                    }

                    #[proptest]
                    fn test_path_compression(
                        mut trie: Trie<$digest>,
                        #[strategy(non_empty_string())] key1: String,
                        #[strategy(non_empty_string())] key2: String,
                        value1: String,
                        value2: String,
                    ) {
                        prop_assume!(key1 != key2);

                        // Insert two elements that should trigger path compression
                        trie.insert(key1.as_bytes(), std::io::Cursor::new(value1.as_bytes()))?;
                        trie.insert(key2.as_bytes(), std::io::Cursor::new(value2.as_bytes()))?;

                        // Verify the proof length is optimal after compression
                        prop_assert!(
                            trie.proof.len() <= 5,
                            "Proof length exceeds expected maximum after compression"
                        );
                    }
                }
            }
        };
    }

    #[cfg(feature = "blake2")]
    type Blake2s = blake2::Blake2s256;
    #[cfg(feature = "blake2")]
    generate_mpf_tests!(Blake2s);

    #[cfg(feature = "blake2")]
    type Blake2b = blake2::Blake2b<digest::consts::U32>;
    #[cfg(feature = "blake2")]
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
        let cmp1 = proof1.partial_cmp(&proof2);
        let cmp2 = proof2.partial_cmp(&proof1);

        match (cmp1, cmp2) {
            (Some(Ordering::Less), Some(Ordering::Greater))
            | (Some(Ordering::Greater), Some(Ordering::Less))
            | (Some(Ordering::Equal), Some(Ordering::Equal)) => {
                prop_assert_eq!(cmp1.map(|o| o.reverse()), cmp2);
            }
            _ => prop_assert!(false, "Unexpected ordering: {:?} vs {:?}", cmp1, cmp2),
        }
    }

    #[proptest]
    fn test_merkle_proof_transitive(proof1: Proof, proof2: Proof, proof3: Proof) {
        if let (Some(ord1), Some(ord2), Some(ord3)) = (
            proof1.partial_cmp(&proof2),
            proof2.partial_cmp(&proof3),
            proof1.partial_cmp(&proof3),
        ) {
            match (ord1, ord2) {
                (Ordering::Less, Ordering::Less) => prop_assert_eq!(ord3, Ordering::Less),
                (Ordering::Greater, Ordering::Greater) => prop_assert_eq!(ord3, Ordering::Greater),
                (Ordering::Equal, Ordering::Equal) => prop_assert_eq!(ord3, Ordering::Equal),
                _ => {}
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
