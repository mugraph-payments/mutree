# µcrdt

µcrdt is a Rust library implementing Conflict-Free Replicated Data Types (CRDTs) with a focus on efficiency and correctness. The primary feature of this library is the Merkle-Patricia Forestry, an optimized variant of the Merkle-Patricia Trie designed for succinct proofs and efficient cryptographic authentication.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Background](#background)
  - [Limitations of Classic Merkle-Patricia Trie](#limitations-of-classic-merkle-patricia-trie)
  - [Why Radix-16?](#why-radix-16)
  - [Optimizing Proof Sizes with Sparse Merkle Trees](#optimizing-proof-sizes-with-sparse-merkle-trees)
- [Implementation Details](#implementation-details)
  - [Node Types](#node-types)
  - [Proof Format](#proof-format)
- [Usage](#usage)
  - [Adding Dependencies](#adding-dependencies)
  - [Basic Operations](#basic-operations)
- [Contributing](#contributing)
- [License](#license)

## Overview

This library provides a highly efficient implementation of a Merkle-Patricia Forestry, which is an authenticated data structure for key-value storage. It offers:

- Efficient key-value storage and retrieval.
- Succinct cryptographic proofs.
- Optimized proof sizes (~130 bytes per step).
- Conflict-free replication properties.

The library is suitable for distributed systems where data consistency and authentication are critical, such as blockchain applications and distributed databases.

## Features

- **Merkle-Patricia Forestry**: An optimized variant of Merkle-Patricia Tries designed to reduce proof sizes while maintaining efficient operations.
- **CRDT Compliant**: Supports Conflict-Free Replicated Data Type properties for eventual consistency in distributed systems.
- **Customizable Hash Functions**: Allows the use of different cryptographic hash functions by leveraging Rust's `Digest` trait.
- **Efficient Proof Verification**: Provides mechanisms for verifying the inclusion and integrity of elements in the trie with minimal overhead.

## Background

### Limitations of Classic Merkle-Patricia Trie

Classic Merkle-Patricia Tries are efficient for data retrieval and offer merkleization benefits. However, they have a significant drawback regarding proof sizes. In a radix-16 trie, proofs contain an average of `log₁₆(n)` steps, where `n` is the number of elements. While this results in fewer steps compared to binary tries, each step is substantially larger because it may include up to 15 neighbor hashes, leading to large proof sizes.

For example, in the worst-case scenario where all steps are full branches, each step requires approximately `15 * 32 = 480` bytes (assuming 32-byte hashes). For a trie with 1 million items, the proof size can be around `480 * log₁₆(1,000,000) ≈ 2,400` bytes, which is substantial, especially in systems with strict size constraints.

### Why Radix-16?

One might question the use of a radix-16 trie given the proof size implications. In an ideal scenario, a radix-2 trie would have smaller proofs, as each step would only be 32 bytes. However, in practical systems like Plutus Core (used in the Cardano blockchain), there are limitations in working with bits directly due to the lack of primitives for bitwise operations. Radix-16 offers a practical middle ground, as nibbles (4 bits) are more manageable with available byte-level operations.

### Optimizing Proof Sizes with Sparse Merkle Trees

To mitigate the large proof sizes in radix-16 tries, this implementation leverages sparse Merkle trees for neighbor hashing within branch nodes. Instead of providing up to 15 neighbor hashes, the neighbors are organized into a small sparse Merkle tree of 16 elements. This approach reduces the required proof data by allowing us to provide only the necessary hashes along the path, rather than all neighbors.

By doing so, the proof size per step decreases from 480 bytes to approximately 130 bytes, significantly reducing the overall proof sizes while maintaining authentication integrity.

## Implementation Details

### Node Types

The Merkle-Patricia Forestry implementation uses a radix-16 trie structure with three types of nodes:

- **Branch**: Nodes with two or more children. Hashes of these nodes are computed using an optimized sparse Merkle tree constructed from their child nodes.
- **Fork**: A special case of a branch node with exactly one non-leaf neighbor. It includes the neighbor's preimage and nibble position.
- **Leaf**: Terminal nodes that contain key-value pairs. The keys and values are stored as hash digests.

### Proof Format

The proof for verifying the inclusion or exclusion of elements in the trie consists of a sequence of steps, which are the nodes encountered along the path to the element. Each step includes a `skip` value corresponding to the length of the common prefix at that level.

#### Branch Step

A branch step includes:

- `skip`: Length of the common prefix.
- `neighbors`: An array representing a sparse Merkle tree of the child nodes' hashes. Only necessary hashes are included, significantly reducing the size.

#### Fork Step

A fork step is used when a node has exactly one neighbor, which is not a leaf. It includes:

- `skip`: Length of the common prefix.
- `neighbor`: Contains the nibble position, prefix, and root hash of the neighbor.

#### Leaf Step

A leaf step represents a terminal node and includes:

- `skip`: Length of the common prefix.
- `key`: Hash of the key.
- `value`: Hash of the value.

## Usage

### Adding Dependencies

To use µcrdt in your Rust project, add the following to your `Cargo.toml`:

```toml
[dependencies]
mucrdt = { git = "https://github.com/cfcosta/mucrdt.git" }
```

### Basic Operations

Below is an example of how to use the Merkle-Patricia Forestry:

```rust
use mucrdt::prelude::*;
use blake2::Blake2s256; // Or any other supported Digest implementation

type Forestry = mucrdt::prelude::Forestry<Blake2s256>;

fn main() -> Result<(), Error> {
    // Create a new empty forestry
    let mut forestry = Forestry::empty();

    // Insert key-value pairs
    forestry.insert(b"key1", b"value1")?;
    forestry.insert(b"key2", b"value2")?;

    // Verify the presence of a key-value pair
    let is_verified = forestry.verify(b"key1", b"value1");
    assert!(is_verified, "Failed to verify key1");

    // Get the root hash for proof purposes
    let root_hash = forestry.root;

    // Merge with another forestry (useful in distributed scenarios)
    let mut other_forestry = Forestry::empty();
    other_forestry.insert(b"key3", b"value3")?;

    forestry.merge(&other_forestry)?;

    // Verify that key3 is now present
    assert!(forestry.verify(b"key3", b"value3"), "Failed to verify key3");

    Ok(())
}
```

**Note**: Replace `Blake2s256` with the digest algorithm of your choice. The library supports any hash function implementing the `Digest` trait.

## Contributing

Contributions are welcome! Please follow these guidelines:

- **Bug Reports and Feature Requests**: Use the [issue tracker](https://github.com/cfcosta/mucrdt/issues) to report bugs or suggest features.
- **Pull Requests**: Fork the repository, make your changes, and submit a pull request.
- **Coding Standards**: Ensure your code complies with Rust's formatting standards by running `cargo fmt`.
- **Testing**: Add unit tests for new features or bug fixes and run `cargo test` before submitting.

## License

This project is dual-licensed under either:

- **MIT License** ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

You may choose either license to govern your use of the software.

For additional licensing arrangements, please contact the maintainers.
