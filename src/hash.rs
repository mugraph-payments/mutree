use std::fmt::{Display, Formatter};

use digest::Digest;
use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;

use crate::prelude::*;

/// Custom Hash type containing the inner field
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Hash([u8; 32]);

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Arbitrary for Hash {
    type Parameters = [u8; 32];
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(inner: Self::Parameters) -> Self::Strategy {
        Just(inner).prop_map(Hash::new).boxed()
    }

    fn arbitrary() -> Self::Strategy {
        any::<[u8; 32]>().prop_map(Hash::new).boxed()
    }
}

impl Hash {
    /// Creates a new Hash from any type that can be converted into [u8; 32].
    pub fn new<T: Into<[u8; 32]>>(data: T) -> Self {
        Hash(data.into())
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        let mut inner = [0u8; 32];
        inner.copy_from_slice(slice);
        Hash(inner)
    }

    /// Returns a zero hash (all bytes set to 0).
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn digest<D: Digest>(data: &[u8]) -> Self {
        let mut hasher = D::new();
        hasher.update(data);
        Hash::from_slice(&hasher.finalize())
    }

    pub fn combine<D: Digest>(left: &Hash, right: &Hash) -> Self {
        let mut hasher = D::new();
        hasher.update(left.as_ref());
        hasher.update(right.as_ref());
        Hash::from_slice(&hasher.finalize())
    }
}

impl Default for Hash {
    fn default() -> Self {
        Hash::zero()
    }
}

impl From<[u8; 32]> for Hash {
    fn from(array: [u8; 32]) -> Self {
        Hash(array)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Hash {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl From<Hash> for [u8; 32] {
    fn from(val: Hash) -> Self {
        val.0
    }
}

impl FromBytes for Hash {
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

    fn to_bytes(&self) -> Self::Output {
        self.0
    }
}

crate::impl_associate_bytes_types!(Hash);

#[cfg(test)]
mod tests {
    use super::*;

    crate::test_to_bytes!(Hash);
    crate::test_to_hex!(Hash);
}

