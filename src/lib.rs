#![feature(coverage_attribute)]
#![deny(
    clippy::correctness,
    clippy::complexity,
    clippy::perf,
    clippy::missing_inline_in_public_items
)]

mod error;

mod forestry;
mod hash;

#[cfg(test)]
pub mod testing;

pub mod prelude {
    pub use digest::Digest;

    pub use crate::{
        error::{Error, Result},
        forestry::{Forestry, Neighbor, Proof, Step},
        hash::Hash,
        CmRDT, CvRDT, FromBytes, FromHex, ToBytes, ToHex,
    };
}

use crate::error::Result;
use digest::Digest;
use proptest::prelude::*;

#[doc(hidden)]
/// This is a hidden module to make the macros defined on this crate available for the users.
pub mod __dependencies {
    pub use paste;
    pub use proptest;
    pub use test_strategy;
}

pub trait CvRDT: Sized + Arbitrary + Default + Clone + PartialEq {
    fn merge(&mut self, other: &Self) -> Result<()>;
}

pub trait CmRDT<T>: Sized + Arbitrary + Default + Clone + PartialEq {
    fn apply(&mut self, other: &T) -> Result<()>;
}

pub trait FromBytes
where
    Self: Sized,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

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

    /// Hashes the value using the specified Digest algorithm.
    ///
    /// This is a convenience method, and automatically derived from `to_bytes`.
    #[inline]
    fn hash_bytes<D: Digest>(&self) -> crate::hash::Hash {
        crate::hash::Hash::digest::<D>(self.to_bytes().as_ref())
    }

    /// Checks if the value (as bytes) is zero.
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

#[macro_export]
macro_rules! impl_associate_bytes_types {
    ($type:ty) => {
        impl std::hash::Hash for $type {
            #[inline]
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.to_bytes().hash(state);
            }
        }

        impl $crate::prelude::FromHex for $type {
            #[inline]
            fn from_hex(input: &str) -> Result<Self> {
                let bytes = hex::decode(input)?;
                Self::from_bytes(&bytes)
            }
        }

        impl $crate::prelude::ToHex for $type {
            #[inline]
            fn to_hex(&self) -> String {
                hex::encode(&ToBytes::to_bytes(self))
            }
        }

        impl std::fmt::LowerHex for $type {
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", hex::encode(self.to_bytes()))
            }
        }

        impl std::fmt::UpperHex for $type {
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", hex::encode_upper(self.to_bytes()))
            }
        }
    };
}
