#![feature(coverage_attribute)]
#![deny(
    clippy::correctness,
    clippy::complexity,
    clippy::perf,
    clippy::missing_inline_in_public_items
)]

mod error;
mod hash;
mod mutree;
mod trie;

#[cfg(test)]
pub mod testing;

pub mod prelude {
    pub use digest::Digest;

    pub use crate::{
        error::{Error, Result},
        hash::Hash,
        mutree::Mutree,
        trie::{Neighbor, Proof, Step, Trie},
        CmRDT,
        CvRDT,
        FromBytes,
        FromHex,
        ToBytes,
        ToHex,
    };
}

use digest::Digest;
use proptest::prelude::*;

use self::prelude::*;

#[cfg(test)]
pub mod __dependencies {
    pub use paste;
    pub use proptest;
    pub use test_strategy;
}

/// A Conflict-free Replicated Data Type (CRDT) that supports state-based replication.
///
/// State-based CRDTs (CvRDTs) maintain their full state and merge with other replicas
/// by combining states. The merge operation must be:
/// - Commutative: order of merges doesn't matter
/// - Associative: grouping of merges doesn't matter
/// - Idempotent: merging same state multiple times has no effect
///
/// # Examples
///
/// ```rust
/// use mutree::prelude::*;
/// use test_strategy::Arbitrary;
///
/// // A simple max counter CRDT
/// #[derive(Debug, Clone, PartialEq, Default, Arbitrary)]
/// struct MaxCounter(u64);
///
/// impl CvRDT for MaxCounter {
///     fn merge(&mut self, other: &Self) -> Result<(), Error> {
///         self.0 = std::cmp::max(self.0, other.0);
///         Ok(())
///     }
/// }
/// ```
pub trait CvRDT: Sized + Arbitrary + Default + Clone + PartialEq {
    /// Merges another CRDT state into this one.
    ///
    /// The merge operation combines the states of two replicas in a way that:
    /// - Is commutative: `a.merge(b) == b.merge(a)`
    /// - Is associative: `(a.merge(b)).merge(c) == a.merge(b.merge(c))`
    /// - Is idempotent: `a.merge(a) == a`
    ///
    /// # Arguments
    ///
    /// * `other` - The other CRDT state to merge with
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the merge was successful, or an error if the merge failed
    fn merge(&mut self, other: &Self) -> Result<(), Error>;
}

/// A Conflict-free Replicated Data Type (CRDT) that supports operation-based replication.
///
/// Operation-based CRDTs (CmRDTs) apply operations rather than merging full states.
/// Operations must be:
/// - Commutative: order of operations doesn't matter
/// - Idempotent: applying same operation multiple times has no effect
pub trait CmRDT<T>: Sized + Arbitrary + Default + Clone + PartialEq {
    fn apply(&mut self, other: &T) -> Result<(), Error>;
}

/// Provides conversion from a byte array representation.
///
/// This trait allows types to be reconstructed from their serialized byte form.
/// Implementations should handle validation and return appropriate errors for
/// invalid input.
pub trait FromBytes
where
    Self: Sized,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

/// Provides conversion to a byte array representation.
///
/// This trait enables types to be serialized into a canonical byte format.
/// The byte representation should be:
/// - Deterministic: same value always produces same bytes
/// - Unambiguous: different values produce different bytes
/// - Complete: contains all necessary information to reconstruct the value
pub trait ToBytes {
    type Output: AsRef<[u8]>;

    /// Converts the value to a representation in bytes.
    fn to_bytes(&self) -> Self::Output;

    /// Converts the value to a representation in bytes, as a vector.
    ///
    /// This is a convenience method, and automatically derived from `to_bytes`.
    #[inline]
    fn to_bytes_vec(&self) -> Vec<u8> {
        self.to_bytes().as_ref().to_vec()
    }

    ///
    /// This is a convenience method, and automatically derived from `to_bytes`.
    #[inline]
    fn hash_bytes<D: Digest>(&self) -> crate::hash::Hash {
        crate::hash::Hash::digest::<D>(self.to_bytes().as_ref())
    }

    ///
    /// This is useful for checking if a value is empty.
    #[inline]
    fn is_zero(&self) -> bool {
        let len = self.to_bytes().as_ref().len();
        self.to_bytes_vec() == vec![0; len]
    }

    /// Provides mutable access to the bytes representation.
    ///
    /// This is an optional method that types can implement if they can
    /// safely provide mutable access to their byte representation.
    /// The default implementation panics.
    #[inline]
    fn to_bytes_mut(&mut self) -> &mut [u8] {
        unimplemented!("to_bytes_mut is not implemented for this type")
    }
}

pub trait FromHex
where
    Self: Sized,
{
    fn from_hex(hex: &str) -> Result<Self>;
}

pub trait ToHex {
    fn to_hex(&self) -> String;
}
