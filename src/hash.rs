use std::fmt::{Display, Formatter};

use digest::Digest;
use proptest::{prelude::*, strategy::BoxedStrategy};

use crate::prelude::*;

/// Custom Hash type containing the inner field
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Hash([u8; 32]);

impl Display for Hash {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Hash {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Arbitrary for Hash {
    type Parameters = [u8; 32];
    type Strategy = BoxedStrategy<Self>;

    #[inline]
    fn arbitrary_with(inner: Self::Parameters) -> Self::Strategy {
        Just(inner).prop_map(Hash::new).boxed()
    }

    #[inline]
    fn arbitrary() -> Self::Strategy {
        any::<[u8; 32]>().prop_map(Hash::new).boxed()
    }
}

impl Hash {
    /// Creates a new Hash from any type that can be converted into [u8; 32].
    #[inline]
    pub fn new<T: Into<[u8; 32]>>(data: T) -> Self {
        Hash(data.into())
    }

    #[inline]
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut inner = [0u8; 32];
        inner.copy_from_slice(slice);
        Hash(inner)
    }

    /// Returns a zero hash (all bytes set to 0).
    #[inline]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    #[inline]
    pub fn digest<D: Digest>(data: &[u8]) -> Self {
        let mut hasher = D::new();
        hasher.update(data);
        Hash::from_slice(&hasher.finalize())
    }

    #[inline]
    pub fn combine<D: Digest>(left: &Hash, right: &Hash) -> Self {
        let mut hasher = D::new();
        hasher.update(left.as_ref());
        hasher.update(right.as_ref());
        Hash::from_slice(&hasher.finalize())
    }
}

impl Default for Hash {
    #[inline]
    fn default() -> Self {
        Hash::zero()
    }
}

impl From<[u8; 32]> for Hash {
    #[inline]
    fn from(array: [u8; 32]) -> Self {
        Hash(array)
    }
}

impl AsRef<[u8]> for Hash {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Hash {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl From<Hash> for [u8; 32] {
    #[inline]
    fn from(val: Hash) -> Self {
        val.0
    }
}

impl std::ops::Index<usize> for Hash {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl std::ops::IndexMut<usize> for Hash {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl FromBytes for Hash {
    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidLength);
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(Hash(array))
    }
}

impl ToBytes for Hash {
    type Output = [u8; 32];

    #[inline]
    fn to_bytes(&self) -> Self::Output {
        self.0
    }
}

crate::impl_associate_bytes_types!(Hash);

#[cfg(test)]
mod tests {
    use blake2::{digest::consts::U32, Blake2b};
    use proptest::prelude::prop::collection::vec;
    use test_strategy::proptest;

    use super::*;

    type Blake2b256 = Blake2b<U32>;

    fn non_empty_string() -> impl Strategy<Value = String> {
        any::<String>().prop_filter("String must not be empty", |s| !s.is_empty())
    }

    #[proptest]
    fn test_hash_indexing(#[strategy(any::<[u8; 32]>())] data: [u8; 32]) {
        let hash = Hash::new(data);
        prop_assert_eq!(hash[0], data[0]);
        prop_assert_eq!(hash[31], data[31]);
    }

    #[proptest]
    fn test_hash_index_mut(mut hash: Hash) {
        hash[0] = 42;
        hash[31] = 255;
        prop_assert_eq!(hash[0], 42);
        prop_assert_eq!(hash[31], 255);
    }

    #[proptest]
    #[should_panic(expected = "index out of bounds")]
    fn test_hash_index_out_of_bounds(hash: Hash) {
        let _ = hash[32];
    }

    #[proptest]
    #[should_panic(expected = "index out of bounds")]
    fn test_hash_index_mut_out_of_bounds(mut hash: Hash) {
        hash[32] = 0;
    }

    #[proptest]
    fn test_path_compression(
        #[strategy(any::<Forestry<Blake2b256>>())] mut trie: Forestry<Blake2b256>,
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

    #[proptest]
    fn test_proof_verification_with_mutations(
        #[strategy(any::<Forestry<Blake2b256>>())] mut trie: Forestry<Blake2b256>,
        #[strategy(non_empty_string())] key: String,
        value: String,
        #[strategy(vec(any::<u8>(), 1..32))] mutation: Vec<u8>,
    ) {
        // Insert valid element
        trie.insert(key.as_bytes(), value.as_bytes())?;
        let valid_proof = trie.proof.clone();

        // Mutate the proof
        let mut mutated_proof = valid_proof.clone();
        let total = mutated_proof.len();

        for (i, m) in mutation.iter().enumerate() {
            if let Some(step) = mutated_proof.get_mut(i % total) {
                match step {
                    Step::Branch { neighbors, .. } => {
                        if let Some(n) = neighbors.get_mut(0) {
                            n[0] ^= m;
                        }
                    }
                    Step::Fork { neighbor, .. } => {
                        neighbor.root[0] ^= m;
                    }
                    Step::Leaf { value, .. } => {
                        value[0] ^= m;
                    }
                }
            }
        }

        // Verify mutated proof fails
        prop_assert!(!trie.verify_proof(
            Hash::digest::<Blake2b256>(key.as_bytes()),
            Hash::digest::<Blake2b256>(value.as_bytes()),
            &mutated_proof
        ));
    }

    #[proptest]
    fn test_sparse_merkle_tree_properties(
        #[strategy(any::<Forestry<Blake2b256>>())] mut trie: Forestry<Blake2b256>,
        #[strategy(vec(non_empty_string(), 1..16))] keys: Vec<String>,
        #[strategy(vec(any::<String>(), 1..16))] values: Vec<String>,
    ) {
        prop_assume!(keys.len() == values.len());

        // Insert multiple elements to test SMT behavior
        for (key, value) in keys.iter().zip(values.iter()) {
            trie.insert(key.as_bytes(), value.as_bytes())?;
        }

        // Verify all elements are present
        for (key, value) in keys.iter().zip(values.iter()) {
            prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()));
        }

        // Verify proof size is logarithmic
        let expected_max_size = (keys.len() as f64).log2().ceil() as usize * 130;
        prop_assert!(
            trie.proof.len() <= expected_max_size,
            "Proof size {} exceeds expected maximum {}",
            trie.proof.len(),
            expected_max_size
        );
    }

    crate::test_to_bytes!(Hash);
    crate::test_to_hex!(Hash);
}
