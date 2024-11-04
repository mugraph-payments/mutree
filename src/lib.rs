#![feature(coverage_attribute)]

mod error;

mod forestry;
mod hash;

pub mod prelude {
    pub use digest::Digest;

    pub use crate::{
        error::{Error, Result},
        forestry::{Forestry, Proof, Step},
        hash::Hash,
        CmRDT, CvRDT, FromBytes, FromHex, Neighbor, ToBytes, ToHex,
    };
}

use crate::{error::Error, error::Result, hash::Hash};
use digest::Digest;
use proptest::prelude::*;

#[doc(hidden)]
/// This is a hidden module to make the macros defined on this crate available for the users.
pub mod __dependencies {
    pub use paste;
    pub use proptest;
    pub use test_strategy;
}

#[macro_export]
macro_rules! test_state_crdt_properties {
    ($type:ty) => {
        $crate::__dependencies::paste::paste! {
            mod [<test_crdt_$type:snake>] {
                use $crate::__dependencies::{
                    proptest::prelude::*,
                    test_strategy,
                };
                use $crate::prelude::{ CvRDT, Result };

                use super::$type;

                fn build_state(items: Vec<&$type>) -> Result<$type> {
                    items.into_iter().try_fold(<$type>::default(), |mut acc, el| {
                        acc.merge(el)?;
                        Ok(acc)
                    })
                }

                #[test_strategy::proptest(fork = false)]
                fn test_changes_are_applied(a: $type) {
                    let mut b = <$type>::default();
                    b.merge(&a)?;
                    prop_assert_eq!(a, b);
                }

                #[test_strategy::proptest(fork = false)]
                fn test_imdepotence(mut a: $type, mut b: $type) {
                    a.merge(&b)?;
                    b.merge(&a)?;
                    prop_assert_eq!(a, b);
                }

                #[test_strategy::proptest(fork = false)]
                fn test_commutativity(a: $type, b: $type) {
                    let ab = build_state(vec![&a, &b])?;
                    let ba = build_state(vec![&a, &b])?;

                    prop_assert_eq!(ab, ba);
                }

                #[test_strategy::proptest(fork = false)]
                fn test_associativity(a: $type, b: $type, c: $type) {
                    let ab = build_state(vec![&a, &b])?;
                    let bc = build_state(vec![&b, &c])?;

                    let mut ab_c = ab.clone();
                    ab_c.merge(&c)?;

                    let mut a_bc = a.clone();
                    a_bc.merge(&bc)?;

                    prop_assert_eq!(&ab_c, &a_bc);
                    prop_assert_eq!(a_bc, ab_c);
                }
            }
        }
    };
}

#[macro_export]
macro_rules! test_op_crdt_properties_inner {
    ($type: ty, $op_type: ty) => {
        use $crate::__dependencies::proptest::prelude::*;
        use $crate::prelude::{CmRDT, Result};

        fn build_op(items: Vec<&$op_type>) -> Result<$type> {
            items
                .into_iter()
                .try_fold(<$type>::default(), |mut acc, el| {
                    acc.apply(el)?;
                    Ok(acc)
                })
        }

        #[test_strategy::proptest(fork = false)]
        fn test_imdepotence(op: $op_type) {
            let mut a = <$type>::default();
            a.apply(&op)?;

            let mut b = a.clone();
            b.apply(&op)?;

            prop_assert_eq!(a, b);
        }

        #[test_strategy::proptest(fork = false)]
        fn test_commutativity(a: $op_type, b: $op_type) {
            let ab = build_op(vec![&a, &b])?;
            let ba = build_op(vec![&a, &b])?;

            prop_assert_eq!(ab, ba);
        }
    };
}

#[macro_export]
macro_rules! test_op_crdt_properties {
    ($type: ty) => {
        $crate::__dependencies::paste::paste! {
            mod [<test_op_crdt_$type:snake>] {
                use super::$type;

                $crate::test_op_crdt_properties_inner!($type, $type);
            }
        }
    };
    ($type: ty, $op_type: ty) => {
        $crate::__dependencies::paste::paste! {
            mod [<test_op_crdt_$type:snake>] {
                use super::{ $type, $op_type };

                $crate::test_op_crdt_properties_inner!($type, $op_type);
            }
        }
    };
}

#[macro_export]
macro_rules! impl_associate_bytes_types {
    ($type:ty) => {
        impl std::hash::Hash for $type {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.to_bytes().hash(state);
            }
        }

        impl $crate::prelude::FromHex for $type {
            fn from_hex(input: &str) -> Result<Self> {
                let bytes = hex::decode(input)?;
                Self::from_bytes(&bytes)
            }
        }

        impl $crate::prelude::ToHex for $type {
            fn to_hex(&self) -> String {
                hex::encode(&ToBytes::to_bytes(self))
            }
        }
    };
}

#[macro_export]
macro_rules! test_to_bytes {
    ($type:ty) => {
        $crate::__dependencies::paste::paste! {
            mod [<test_to_bytes_$type:snake>] {
                use $crate::__dependencies::{
                    proptest::prelude::*,
                    test_strategy,
                };

                use $crate::prelude::*;
                use super::$type;

                $crate::test_to_hex!($type);

                #[test]
                fn test_default_is_zero() {
                    assert!(<$type>::default().is_zero());
                }

                #[test_strategy::proptest(fork = false)]
                fn test_is_zero_is_same_as_zero_bytes(item: $type) {
                    prop_assert_eq!(
                        item.is_zero(),
                        item.to_bytes() == <$type>::default().to_bytes()
                    );
                }

                #[test_strategy::proptest(fork = false)]
                fn test_roundtrip(a: $type) {
                    prop_assert_eq!(a.clone(), <$type>::from_bytes(&a.to_bytes())?);
                }

                #[test_strategy::proptest(fork = false)]
                fn test_output_consistency(a: $type) {
                    prop_assert_eq!(a.to_bytes(), <$type>::from_bytes(&a.to_bytes())?.to_bytes());
                }

                #[test_strategy::proptest(fork = false)]
                fn test_is_different_on_different_objects(a: $type, b: $type) {
                    prop_assert_eq!(a == b, a.to_bytes() == b.to_bytes());
                }
            }
        }
    };
}

#[macro_export]
macro_rules! test_to_hex {
    ($type:ty) => {
        $crate::__dependencies::paste::paste! {
            mod [<test_to_hex_$type:snake>] {
                use $crate::__dependencies::{
                    proptest::prelude::*,
                    test_strategy,
                };

                use $crate::prelude::*;
                use super::$type;

                #[test_strategy::proptest(fork = false)]
                fn test_roundtrip(a: $type) {
                    prop_assert_eq!(a.clone(), <$type>::from_hex(&a.to_hex())?);
                }

                #[test_strategy::proptest(fork = false)]
                fn test_output_consistency(a: $type) {
                    prop_assert_eq!(a.to_hex(), <$type>::from_hex(&a.to_hex())?.to_hex());
                }

                #[test_strategy::proptest(fork = false)]
                fn test_is_different_on_different_objects(a: $type, b: $type) {
                    prop_assert_eq!(a == b, a.to_hex() == b.to_hex());
                }
            }
        }
    };
}

#[macro_export]
macro_rules! prop_assert_changes {
    ($action: expr, $value: expr) => {
        let old_value = $value.clone();

        prop_assert_eq!($value, old_value);

        $action;

        prop_assert_ne!($value, old_value);
    };
}

#[macro_export]
macro_rules! prop_assert_does_not_change {
    ($action: expr, $value: expr) => {
        let old_value = $value.clone();

        $action;

        prop_assert_eq!($value, old_value);
    };
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
    fn to_bytes_vec(&self) -> Vec<u8> {
        self.to_bytes().as_ref().to_vec()
    }

    /// Hashes the value using the specified Digest algorithm.
    ///
    /// This is a convenience method, and automatically derived from `to_bytes`.
    fn hash_bytes<D: Digest>(&self) -> crate::hash::Hash {
        crate::hash::Hash::digest::<D>(self.to_bytes().as_ref())
    }

    /// Checks if the value (as bytes) is zero.
    ///
    /// This is useful for checking if a value is empty.
    fn is_zero(&self) -> bool {
        let len = self.to_bytes().as_ref().len();
        self.to_bytes_vec() == vec![0; len]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct Neighbor {
    /// The nibble (4-bit value) of the neighbor.
    pub nibble: u8,
    /// The remaining prefix of the neighbor's key.
    pub prefix: Vec<u8>,
    /// The hash digest of the neighbor's subtree.
    pub root: Hash,
}

impl Arbitrary for Neighbor {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<u8>(), any::<Vec<u8>>(), any::<Hash>())
            .prop_map(|(nibble, prefix, root)| Neighbor {
                nibble,
                prefix,
                root,
            })
            .boxed()
    }
}

impl ToBytes for Neighbor {
    type Output = Vec<u8>;

    fn to_bytes(&self) -> Self::Output {
        let mut bytes = vec![self.nibble];
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(self.root.as_ref());
        bytes
    }
}

impl FromBytes for Neighbor {
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
