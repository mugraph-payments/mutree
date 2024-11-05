use std::fmt::{self, Display, Formatter, LowerHex, UpperHex};

use digest::Digest;
use proptest::{prelude::*, strategy::BoxedStrategy};

use crate::prelude::*;

/// Custom Hash type containing the inner field
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Hash([u8; 32]);

impl Display for Hash {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Hash {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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

impl std::hash::Hash for Hash {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl FromHex for Hash {
    #[inline]
    fn from_hex(input: &str) -> Result<Self> {
        let bytes = hex::decode(input)?;
        Self::from_bytes(&bytes)
    }
}

impl ToHex for Hash {
    #[inline]
    fn to_hex(&self) -> String {
        hex::encode(&ToBytes::to_bytes(self))
    }
}

impl LowerHex for Hash {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl UpperHex for Hash {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode_upper(self.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;

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

    crate::test_to_bytes!(Hash);
    crate::test_to_hex!(Hash);
}
