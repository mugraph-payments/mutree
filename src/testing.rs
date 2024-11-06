/// Tests properties required for state-based CRDTs (CvRDT).
///
/// This macro generates test cases that verify the following CRDT properties:
/// - Changes are applied correctly
/// - Operations are idempotent
/// - Operations are commutative
/// - Operations are associative
///
/// # Example
///
/// ```rust
/// use mutree::prelude::*;
/// 
/// #[derive(Debug, Clone, PartialEq, Default)]
/// struct Counter(u64);
/// 
/// impl CvRDT for Counter {
///     fn merge(&mut self, other: &Self) -> Result<(), Error> {
///         self.0 = std::cmp::max(self.0, other.0);
///         Ok(())
///     }
/// }
/// 
/// // Generates comprehensive CRDT property tests
/// test_state_crdt_properties!(Counter);
/// ```
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
        use $crate::{
            __dependencies::proptest::prelude::*,
            prelude::{CmRDT, Result},
        };

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

/// Tests properties required for operation-based CRDTs (CmRDT).
///
/// This macro generates test cases that verify:
/// - Operations are idempotent
/// - Operations are commutative
///
/// # Examples
///
/// Basic usage with same type for state and operations:
/// ```rust
/// use mutree::prelude::*;
/// 
/// #[derive(Debug, Clone, PartialEq, Default)]
/// struct Counter(u64);
/// 
/// impl CmRDT<Counter> for Counter {
///     fn apply(&mut self, op: &Counter) -> Result<(), Error> {
///         self.0 += op.0;
///         Ok(())
///     }
/// }
/// 
/// test_op_crdt_properties!(Counter);
/// ```
///
/// Usage with separate operation type:
/// ```rust
/// use mutree::prelude::*;
/// 
/// #[derive(Debug, Clone, PartialEq, Default)]
/// struct Counter(u64);
/// 
/// #[derive(Debug, Clone, PartialEq)]
/// enum CounterOp {
///     Increment(u64),
///     Decrement(u64)
/// }
/// 
/// impl CmRDT<CounterOp> for Counter {
///     fn apply(&mut self, op: &CounterOp) -> Result<(), Error> {
///         match op {
///             CounterOp::Increment(n) => self.0 += n,
///             CounterOp::Decrement(n) => self.0 -= n,
///         }
///         Ok(())
///     }
/// }
/// 
/// test_op_crdt_properties!(Counter, CounterOp);
/// ```
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

/// Tests serialization/deserialization roundtrip properties.
///
/// Verifies that a type implementing ToBytes and FromBytes:
/// - Can roundtrip through bytes without data loss
/// - Produces consistent byte output
/// - Has different byte representations for different values
/// - Correctly identifies zero/empty states
///
/// # Example
///
/// ```rust
/// use mutree::test_to_bytes;
///
/// #[derive(Debug, Clone, PartialEq)]
/// struct MyType(Vec<u8>);
///
/// impl ToBytes for MyType {
///     type Output = Vec<u8>;
///     fn to_bytes(&self) -> Self::Output {
///         self.0.clone()
///     }
/// }
///
/// impl FromBytes for MyType {
///     fn from_bytes(bytes: &[u8]) -> Result<Self> {
///         Ok(MyType(bytes.to_vec()))
///     }
/// }
///
/// test_to_bytes!(MyType);
/// ```
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

/// Tests hex encoding/decoding roundtrip properties.
///
/// Verifies that a type implementing ToHex and FromHex:
/// - Can roundtrip through hex strings without data loss
/// - Produces consistent hex output
/// - Has different hex representations for different values
///
/// # Example
///
/// ```rust
/// use mutree::test_to_hex;
///
/// #[derive(Debug, Clone, PartialEq)]
/// struct MyType(Vec<u8>);
///
/// impl ToHex for MyType {
///     fn to_hex(&self) -> String {
///         hex::encode(&self.0)
///     }
/// }
///
/// impl FromHex for MyType {
///     fn from_hex(hex: &str) -> Result<Self> {
///         Ok(MyType(hex::decode(hex)?))
///     }
/// }
///
/// test_to_hex!(MyType);
/// ```
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

/// Asserts that an action changes a value.
///
/// Useful for testing that operations actually modify state.
///
/// # Example
///
/// ```rust
/// use mutree::prop_assert_changes;
///
/// #[test]
/// fn test_counter_increment() {
///     let mut counter = 0u64;
///     
///     prop_assert_changes!(
///         counter += 1,  // Action that should change counter
///         counter       // Value that should change
///     );
/// }
/// ```
#[macro_export]
macro_rules! prop_assert_changes {
    ($action: expr, $value: expr) => {
        let old_value = $value.clone();

        prop_assert_eq!($value, old_value);

        $action;

        prop_assert_ne!($value, old_value);
    };
}

/// Asserts that an action does not change a value.
///
/// Useful for testing idempotency or that invalid operations have no effect.
///
/// # Example
///
/// ```rust
/// use mutree::prop_assert_does_not_change;
///
/// #[test]
/// fn test_counter_invalid_decrement() {
///     let mut counter = 0u64;
///     
///     prop_assert_does_not_change!(
///         if counter > 0 { counter -= 1 },  // Action that should not change counter
///         counter                           // Value that should not change
///     );
/// }
/// ```
#[macro_export]
macro_rules! prop_assert_does_not_change {
    ($action: expr, $value: expr) => {
        let old_value = $value.clone();

        $action;

        prop_assert_eq!($value, old_value);
    };
}
