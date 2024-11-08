use std::{
    cmp::Ordering,
    ops::{Deref, DerefMut},
};

use proptest::{collection::vec, prelude::*};

use super::Step;
use crate::prelude::Hash;

/// A complete proof in a Merkle-Patricia Trie.
///
/// A proof consists of a sequence of steps that authenticate a path through the trie,
/// allowing verification of membership, insertion, or deletion operations. The proof
/// structure is optimized to minimize size while maintaining security:
///
/// - Branch steps use a mini Sparse-Merkle Tree requiring only 4 hashes
/// - Fork steps include complete neighbor information for reconstruction
/// - Leaf steps contain the actual key-value pair hashes
///
/// The proof size is bounded by O(log₁₆(n)) steps, where each step requires at most
/// 130 bytes (for Branch nodes), significantly improving upon traditional MPT proofs
/// while maintaining similar verification costs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Proof(Vec<Step>);

impl Proof {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn steps(&self) -> &[Step] {
        &self.0
    }

    #[inline]
    pub fn iter_steps(&self) -> impl Iterator<Item = &Step> {
        self.0.iter()
    }

    #[inline]
    pub fn root(&self) -> Hash {
        if self.is_empty() {
            return Hash::default();
        }

        match self.last().unwrap() {
            Step::Branch { neighbors, .. } => neighbors[0],
            Step::Fork { neighbor, .. } => neighbor.root,
            Step::Leaf { value, .. } => *value,
        }
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&Step> {
        self.0.get(index)
    }

    #[inline]
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Step) -> bool,
    {
        self.0.retain(f);
    }

    #[inline]
    pub fn remove(&mut self, index: usize) -> Option<Step> {
        if index < self.0.len() {
            Some(self.0.remove(index))
        } else {
            None
        }
    }

    #[inline]
    pub fn push(&mut self, step: Step) {
        self.0.push(step);
    }

    #[inline]
    pub fn extend<I: IntoIterator<Item = Step>>(&mut self, iter: I) {
        self.0.extend(iter);
    }

    #[inline]
    pub fn set(&mut self, index: usize, step: Step) {
        self.0[index] = step;
    }
}

impl Deref for Proof {
    type Target = [Step];

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Proof {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<Step>> for Proof {
    #[inline(always)]
    fn from(steps: Vec<Step>) -> Self {
        Proof(steps)
    }
}

impl From<Proof> for Vec<Step> {
    #[inline(always)]
    fn from(proof: Proof) -> Self {
        proof.0
    }
}

impl IntoIterator for Proof {
    type Item = Step;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Proof {
    type Item = &'a Step;
    type IntoIter = std::slice::Iter<'a, Step>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut Proof {
    type Item = &'a mut Step;
    type IntoIter = std::slice::IterMut<'a, Step>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl PartialOrd for Proof {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Compare the lengths of the proof vectors first
        match self.len().partial_cmp(&other.len()) {
            Some(Ordering::Equal) => {}
            ord => return ord,
        }

        // Use iterators instead of cloning
        self.iter()
            .zip(other.iter())
            .try_fold(Ordering::Equal, |acc, (a, b)| {
                match (acc, a.partial_cmp(b)?) {
                    (Ordering::Equal, ord) => Some(ord),
                    (ord, _) => Some(ord),
                }
            })
    }
}

impl Arbitrary for Proof {
    type Parameters = usize;
    type Strategy = BoxedStrategy<Self>;

    #[inline]
    fn arbitrary_with(depth: Self::Parameters) -> Self::Strategy {
        vec(any::<Step>(), 0..=depth).prop_map(Proof).boxed()
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;

    #[cfg(feature = "blake3")]
    /// Tests an optimization that is possible on blake3 because the hash function itself is
    /// incremental.
    mod blake3_tests {
        use std::io::Cursor;

        
        use crate::prelude::*;

        #[test]
        fn test_large_value_insert() -> Result<(), Error> {
            let mut trie = Trie::<blake3::Hasher>::empty();
            let key = b"test_key";
            let large_data = vec![0u8; 1_000_000]; // 1MB of data
            let reader = Cursor::new(large_data.clone());

            let value_hash = trie.insert(key, reader)?;
            assert!(trie.verify(key, &large_data));

            // Verify same result with direct data
            let mut regular_trie = Trie::<blake3::Hasher>::empty();
            let regular_hash = regular_trie.insert(key, Cursor::new(&large_data))?;
            assert_eq!(value_hash, regular_hash);

            Ok(())
        }

        #[test]
        fn test_incremental_hashing() -> Result<(), Error> {
            let mut trie = Trie::<blake3::Hasher>::empty();
            let key = b"test_key";
            let data = vec![1u8; 100_000];

            let hash1 = trie.insert(key, Cursor::new(&data))?;

            let mut regular_trie = Trie::<blake3::Hasher>::empty();
            let hash2 = regular_trie.insert(key, Cursor::new(&data))?;

            assert_eq!(hash1, hash2);
            assert_eq!(trie.root, regular_trie.root);

            Ok(())
        }
    }

    #[proptest]
    fn test_proof_push_and_pop(mut proof: Proof, step: Step) {
        let original_len = proof.len();
        proof.push(step.clone());

        prop_assert_eq!(proof.len(), original_len + 1);
        prop_assert_eq!(proof.last(), Some(&step));

        let popped = proof.remove(proof.len() - 1);

        prop_assert_eq!(popped, Some(step));
        prop_assert_eq!(proof.len(), original_len);
    }

    #[proptest]
    fn test_proof_extend_and_retain(mut proof: Proof, additional_steps: Vec<Step>) {
        let original_len = proof.len();
        proof.extend(additional_steps.clone());
        prop_assert_eq!(proof.len(), original_len + additional_steps.len());

        proof.retain(|step| matches!(step, Step::Leaf { .. }));
        prop_assert!(proof.iter().all(|step| step.is_leaf()));
    }

    #[test]
    fn test_empty_root() {
        assert_eq!(Proof::new().root(), Hash::default());
    }

    #[proptest]
    fn test_is_empty(step: Step) {
        let mut proof = Proof::new();
        prop_assert!(proof.is_empty());
        proof.push(step);
        prop_assert!(!proof.is_empty());
    }
}
