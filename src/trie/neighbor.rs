use test_strategy::Arbitrary;

use super::{FromBytes, ToBytes};
use crate::{
    error::{Error, Result},
    hash::Hash,
};

/// A neighbor node in a Merkle-Patricia Trie.
///
/// Neighbors represent adjacent nodes in the trie structure and are used to construct
/// proof steps. Each neighbor contains:
/// - A nibble (4-bit value) indicating its position
/// - A prefix representing the common path segment
/// - A root hash authenticating its subtree
///
/// This structure is particularly important for Fork steps, where having the complete
/// neighbor information allows proper verification and reconstruction of the trie.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Arbitrary)]
pub struct Neighbor {
    /// The 4-bit position (0-15) of this neighbor in its parent branch
    pub nibble: u8,
    /// The common prefix shared with its siblings, encoded as bytes
    pub prefix: Vec<u8>,
    /// The root hash of this neighbor's subtree
    pub root: Hash,
}

impl ToBytes for Neighbor {
    type Output = Vec<u8>;

    #[inline]
    fn to_bytes(&self) -> Self::Output {
        let mut bytes = vec![self.nibble];
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(self.root.as_ref());
        bytes
    }
}

impl FromBytes for Neighbor {
    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 33 {
            return Err(Error::Deserialization(
                "Invalid length for Neighbor".to_string(),
            ));
        }

        let nibble = bytes[0];
        let prefix = bytes[1..bytes.len() - 32].to_vec();
        let root = Hash::from_slice(&bytes[bytes.len() - 32..]);

        Ok(Neighbor {
            nibble,
            prefix,
            root,
        })
    }
}
