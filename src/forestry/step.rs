use core::cmp::Ordering;

use proptest::{array::uniform4, prelude::*};

use crate::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Branch { skip: usize, neighbors: [Hash; 4] },
    Fork { skip: usize, neighbor: Neighbor },
    Leaf { skip: usize, key: Hash, value: Hash },
}

impl Step {
    #[inline(always)]
    pub fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf { .. })
    }

    #[inline(always)]
    pub fn is_branch(&self) -> bool {
        matches!(self, Self::Branch { .. })
    }

    #[inline(always)]
    pub fn is_fork(&self) -> bool {
        matches!(self, Self::Fork { .. })
    }
}

impl ToBytes for Step {
    type Output = Vec<u8>;

    #[inline]
    fn to_bytes(&self) -> Self::Output {
        match self {
            Step::Branch { skip, neighbors } => {
                let mut bytes = vec![0u8]; // 0 indicates Branch
                bytes.extend_from_slice(&skip.to_be_bytes());
                for neighbor in neighbors {
                    bytes.extend_from_slice(neighbor.as_ref());
                }
                bytes
            }
            Step::Fork { skip, neighbor } => {
                let mut bytes = vec![1u8]; // 1 indicates Fork
                bytes.extend_from_slice(&skip.to_be_bytes());
                bytes.extend(neighbor.to_bytes());
                bytes
            }
            Step::Leaf { skip, key, value } => {
                let mut bytes = vec![2u8]; // 2 indicates Leaf
                bytes.extend_from_slice(&skip.to_be_bytes());
                bytes.extend_from_slice(key.as_ref());
                bytes.extend_from_slice(value.as_ref());
                bytes
            }
        }
    }
}

impl FromBytes for Step {
    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::Deserialization("Empty input".to_string()));
        }

        match bytes[0] {
            0 => {
                // Branch
                if bytes.len() < 1 + std::mem::size_of::<usize>() + 4 * 32 {
                    return Err(Error::Deserialization(
                        "Invalid length for Branch".to_string(),
                    ));
                }
                let skip = usize::from_be_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                let mut neighbors = [Hash::default(); 4];
                for (i, neighbor) in neighbors.iter_mut().enumerate() {
                    let start = 1 + std::mem::size_of::<usize>() + i * 32;
                    *neighbor = Hash::from_slice(&bytes[start..start + 32]);
                }
                Ok(Step::Branch { skip, neighbors })
            }
            1 => {
                // Fork
                if bytes.len() < 1 + std::mem::size_of::<usize>() + 33 {
                    return Err(Error::Deserialization(
                        "Invalid length for Fork".to_string(),
                    ));
                }
                let skip = usize::from_be_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                let neighbor = Neighbor::from_bytes(&bytes[1 + std::mem::size_of::<usize>()..])?;
                Ok(Step::Fork { skip, neighbor })
            }
            2 => {
                // Leaf
                if bytes.len() < 1 + std::mem::size_of::<usize>() + 64 {
                    return Err(Error::Deserialization(
                        "Invalid length for Leaf".to_string(),
                    ));
                }
                let skip = usize::from_be_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                let key = Hash::from_slice(
                    &bytes[1 + std::mem::size_of::<usize>()..1 + std::mem::size_of::<usize>() + 32],
                );
                let value = Hash::from_slice(
                    &bytes[1 + std::mem::size_of::<usize>() + 32
                        ..1 + std::mem::size_of::<usize>() + 64],
                );
                Ok(Step::Leaf { skip, key, value })
            }
            _ => Err(Error::Deserialization("Invalid Step type".to_string())),
        }
    }
}

impl Arbitrary for Step {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    #[inline]
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            (any::<usize>(), uniform4(any::<Hash>()))
                .prop_map(|(skip, neighbors)| Step::Branch { skip, neighbors }),
            (any::<usize>(), any::<Neighbor>())
                .prop_map(|(skip, neighbor)| Step::Fork { skip, neighbor }),
            (any::<usize>(), any::<Hash>(), any::<Hash>())
                .prop_map(|(skip, key, value)| Step::Leaf { skip, key, value })
        ]
        .boxed()
    }
}

impl PartialOrd for Step {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (
                Step::Branch {
                    skip: s1,
                    neighbors: n1,
                },
                Step::Branch {
                    skip: s2,
                    neighbors: n2,
                },
            ) => match s1.partial_cmp(s2) {
                Some(Ordering::Equal) => n1.partial_cmp(n2),
                ord => ord,
            },
            (
                Step::Fork {
                    skip: s1,
                    neighbor: n1,
                },
                Step::Fork {
                    skip: s2,
                    neighbor: n2,
                },
            ) => match s1.partial_cmp(s2) {
                Some(Ordering::Equal) => n1.partial_cmp(n2),
                ord => ord,
            },
            (
                Step::Leaf {
                    skip: s1,
                    key: k1,
                    value: v1,
                },
                Step::Leaf {
                    skip: s2,
                    key: k2,
                    value: v2,
                },
            ) => match s1.partial_cmp(s2) {
                Some(Ordering::Equal) => match k1.partial_cmp(k2) {
                    Some(Ordering::Equal) => v1.partial_cmp(v2),
                    ord => ord,
                },
                ord => ord,
            },
            // Define an arbitrary order between different Step variants
            (Step::Branch { .. }, _) => Some(Ordering::Less),
            (_, Step::Branch { .. }) => Some(Ordering::Greater),
            (Step::Fork { .. }, Step::Leaf { .. }) => Some(Ordering::Less),
            (Step::Leaf { .. }, Step::Fork { .. }) => Some(Ordering::Greater),
        }
    }
}

impl Default for Step {
    #[inline]
    fn default() -> Self {
        Step::Branch {
            skip: 0,
            neighbors: [Hash::default(); 4],
        }
    }
}

impl std::hash::Hash for Step {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl FromHex for Step {
    #[inline]
    fn from_hex(input: &str) -> Result<Self> {
        let bytes = hex::decode(input)?;
        Self::from_bytes(&bytes)
    }
}

impl ToHex for Step {
    #[inline]
    fn to_hex(&self) -> String {
        hex::encode(&ToBytes::to_bytes(self))
    }
}

impl std::fmt::LowerHex for Step {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl std::fmt::UpperHex for Step {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode_upper(self.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::test_to_bytes!(Step);
}
