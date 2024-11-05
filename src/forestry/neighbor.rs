use test_strategy::Arbitrary;

use super::{FromBytes, ToBytes};
use crate::{
    error::{Error, Result},
    hash::Hash,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Arbitrary)]
pub struct Neighbor {
    pub nibble: u8,
    pub prefix: Vec<u8>,
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
