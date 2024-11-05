# Technical Analysis

>[!WARNING]
>This is a concatenated document with the information on the [Merkle-Patricia Forestry Wiki](https://github.com/aiken-lang/merkle-patricia-forestry/wiki).

## Forestry

### The problem with (classic) Merkle-Patricia Trie

Is it all? No.

Merkle-Patricia Trie are extremely efficient for retrieving data, and the merkleization is quite satisfactory. However, one of their big downside regards the size of the proof. With tries of radix 16, we end up with proofs containing an average of `log_16(n)` steps, where `n` is the size of the tree; which is great because it is ~3 times less steps than for binary tries! But... each step is a lot bigger.

Indeed, most proof steps will usually contain a serie of _Branch_ steps, and ends with a _Fork_ or a _Leaf_ step. This is because we chose keys to be hash digests, and keys will easily conflict at the beginning but won't likely have long prefixes. To make reasoning simpler, let's just consider the worse case where all steps are in fact full Branch steps. Each step requires therefore about `15 * 32 = 480` bytes. For a trie of 1M items, that's `480 * log_16(1000000)` ~ 2400 bytes! That is quite a lot considering a transaction max size of 16,384 bytes, which must also contain other data needed for subsequent logic.

### Why radix-16?

One might ask: but why use radix 16 if they lead to such large proofs? A Merkle-Patricia Trie of radix-2 would have about `log_2(n)` steps of only 32 bytes each. So for 1M items, that's only `32 * log_2(1000000)` = 442 bytes of proof.

That is true. And in an ideal world, this is what we would do. But in our current world, Plutus Core doesn't provide any primitives for working with bits. So it is unpractical to manipulate binary tries whose branching is done on bits while having only fast primitives for working with _bytes_. Radix 16 offers a nice middleground because they work with half-bytes, which means that nibble are only a modulo or a division away.

But there's a trick.

### Trees in tries

In fact, the reason we must provide up to 15 neighbors stems from how we construct the hash of branch nodes by simply concatenating the neighbors' hashes together. When verifying the proof, we must insert the node's being verified at the right position so that we can calculate the hash that authenticate that particular structure. And, we do actually know of an authenticated structure that provides succinct proofs: Merkle Trees! And more specifically, Sparse-Merkle Trees in this case, because we might have anywhere between 1 and 15 neighbors.

So, if we construct the hash of all neighbors as the hash of a tiny Sparse-Merkle tree of 16 elements where neighbors are ordered according to their respective nibbles, we effectively end up trading some computing power for smaller proofs. Because once organized as a Merkle Tree, we no longer need to provide all 15 hashes, but only the neighbor nodes on the path. Such a binary tree of 16 elements will always have a depth of 4:

```
       ┌───────┴───────┐
   ┌───┴───┐       ┌───┴───┐
 ┌─┴─┐   ┌─┴─┐   ┌─┴─┐   ┌─┴─┐
┌┴┐ ┌┴┐ ┌┴┐ ┌┴┐ ┌┴┐ ┌┴┐ ┌┴┐ ┌┴┐
0 1 2 3 4 5 6 7 8 9 a b c d e f
```

When neighbors are missing, we replace them with "null hashes" which we choose to be, by convention, 32 null bytes. This allows to consistently operate on a tree of 16 elements, as well as preventing malleability of the neighbors. From there, to recompute the hash of a branch node, we must always provide exactly 4 hashes corresponding to the hash of the neighbor sub-trees at depth 1, 2, 3 and the neighboring leaf at 4.

Note that this also works for branches with only 2 neighbors. And since null hashes are known, entire portion of the trees can be 'cached' at each level making it possible to recover the hash of a root tree in always exactly 4 steps (thus limiting also the overhead in computation).

This reduces the proof size of each step from 480 bytes down to 130 bytes, while also preserving small step sizes for _Leaf_ and _Fork_ scenarios. Our implementation also shows that the overhead in memory and cpu units is somewhere around 30% of the original cost with an overall verification cost that remains very acceptable (a fraction of the total budget which is still less than the fraction of the proof size in terms of the transaction max size).

# Proof Format

## Overview

We distinguish three kinds of proof steps: Branch, Fork and Leaf. Each step contains a `skip` value which corresponds to the length of the common prefix at that particular level.

Since the prefix is a portion of the path (itself obtained by hashing the key), we need not to provide the whole prefix. The length is sufficient to recover it.

Note also that the `Fork` and `Leaf` steps may seem like an optimization when looking only at the proof from an inclusion perspective; but they are actually necessary steps to verify insertion and deletion proofs (which verifies the proof from an exclusion standpoint, and thus require the full neighbor when there's only one).

## Branch

The most common case encountered for every level that has 3+ nodes (or 2+ neighbors depending how you look at it). The `neighbors` array is an array of `4 * 32 = 130` bytes which corresponds to 4 hash digests.

These 4 digests are in reality a Merkle proof of a tiny binary Sparse-Merkle Tree of size 16 corresponding to all the nodes at that branch arranged according to their nibble (`0` leftmost, `f` rightmost).

- The first 32 bytes of the `neighbors` array is the root hash of the
  top-most neighbor sub-tree containing 8 nodes.

- The last 32 bytes of the `neighbors` array is the direct neighbor of
  the node if any, or a null hash (32 times `0` bits).

To recover the hash of a `Branch` level, we must compute the following:

```aiken
blake2b_256(prefix | sparse_merkle_root([node, ...neighbors]))
```

where `sparse_merkle_root` denotes the Merkle root hash obtained from
arranging the 16 nodes by their nibbles as described, using null hashes for
absent neighbors.

## Fork

A `Fork` is a special `Branch` case where there's only one neighbor which is not a `Leaf`.

The step contains the full neighbor's preimage, as well as the nibble at which it sits. From there, we can recover the hash of a `Fork` level by computing:

```aiken
blake2b_256(prefix | sparse_merkle_root([node, blake2b_256(neighbor.prefix | neighbor.root)]))
```

The `neighbor.nibble` indicates the location of the neighbor in the Sparse Merkle Tree, whereas the one from the node being proved is given by its path at that particular location.

## Leaf

A `Leaf` is a special `Branch` case where there's only one neighbor which is a leaf of the trie.

The `key` and `value` corresponds to the **hash digests** of the neighbor's key and value respectively. Note that while we provide the full key, the proof only truly requires a suffix of the key up to the moment it separates from the node's path. The first bits of the keys are thus usually ignored and are only kept to make the proof more convenient to generate.

## Notations & definitions

#### Byte arrays

We represent byte arrays as sequences of bytes between curly braces `{` and `}`, with each byte prefixed with a pound sign `#`. For example: `{ #01, #fa }`

#### Nibbles

We call _nibble_ an hexadecimal digit encoded over 4 bits. Sequences of nibbles are presented as text-strings between chevrons `<` and `>`, but treated as byte-strings when encoded. So for example, the sequence of 4 nibbles `<abcd>` is in fact a byte array of length 2: `{#ab, #cd}`. For odd sequences, we prepend a `0` nibble. So `<abc>` becomes `{#0a, #bc}`.

#### Indexing

We denote `foo_i` the i-th element of an array named _foo_. When _foo_ is a sequence of nibbles, then `foo_i` refers to the ith nibble.

#### Hashing

We denote `[ a ]` the hash digest of an object `a` through some chosen hashing algorithm.

#### Concatenation

We denote `,` the concatenation of two byte-arrays.

#### key → value

We write `key → value` a _key_ mapped to a _value_.

## Merkle-Patricia Tries

### Patricia Tries

We consider a persistent tree-structure that maps arbitrary keys to values. We store values at the leaves of the trie, and organise the trie lexicographically according to the key. Nodes that only have one children are merged with their parent, effectively factoring out common portion of the keys which we call prefixes. For example, if we consider a binary tree with the following elements: `<000> → a`, `<111001> → b`, `<1111> → c`. We obtain the the following:

```
  ┌─────┴─────┐
<000>       <111>
  │       ┌───┴────┐
  │     <001>     <1>
  │       │        │
  a       b        c
```

Patricia tries, however, do not encode every bits of keys along the path. Instead, the structure of the trie itself is used to reconstruct the key (and vice-versa). Said differently, bits are implicitly encoded in the position of branches. As such:

```
  ┌─────┴─────┐
<00>         <11>
  │       ┌───┴────┐
  │      <01>      <>
  │       │        │
  a       b        c
```

This approach guarantees that inserting a new item in the trie always lead to the creation of at most two nodes -- only one most of the time. Our construction uses tries of radix 16 (corresponding to possible bits value of hexadecimal digits). And, we distinguish two types of nodes:

- _Branch_ nodes with at least 2 and up to 16 branches each corresponding to a nibble.
- _Leaf_ nodes with exactly one branch. They hold the (serialisable) values and the remaining part of the key which we typically refer to as _suffix_.

### Merkling

What gives the 'merkle' aspect to the structure is how each node holds a hash that captures its value (for leaves) or children (for branches), as well as the suffix/prefix for that node. We compute hashes of nodes as follows:

- `[ head(suffix), tail(suffix), [ value ] ]` for leaves
- `[ nibbles(prefix), [ children_0, ..., children_n ] ]` for branches [^1]

Where:

- `children_i` refers to the hash of the ith children

- `nibble(prefix)` is a byte-array whose bytes correspond to the concatenation
  of each nibbles in the prefix, left-padded with 0. For example, `nibble(<1a4d>) = {#01, #0a, #04, #0d}`

- `head` and `tail` suffix are functions defined as:
  - `head(suffix)`:
    - when suffix has an odd number of nibbles, returns `<00, 0, suffix_0>`
    - when suffix has an even number of nibbles, returns `<ff>`

  - `tail(suffix)`:
    - when suffix has an odd number of nibbles, returns suffix minus the first nibble.
    - when suffix has an even number of nibbles, returns suffix.

  This is necessary to cope with the ambiguity that comes from and odd number
  of nibbles. This is because nibbles are, in fact, half bytes (4 bits). So for
  example, the sequence `<abc>` and `<0abc>` have the same byte representations which
  can create conflicts (two different nodes having the same hash!) unless we ensure
  to disambiguate both cases.

> [!NOTE]
>
> The value and children are hashed an extra-round. While it may seem unnecessary, this is crucial in order to provide proofs for insertion and deletion. Proof of membership could however be obtained with a much simpler hashing structure. This will make more sense soon-enough.

The combination of those techniques give us a structure called Merkle-Patricia Trie, useful to prove membership, insertion and deletion of items in the trie from just a root hash and a succinct proof. The entire trie is also fully authenticated and protected from tampering. Indeed, any change to any part of the trie causes a node's hash to change and all the parent nodes above, up to the trie root hash.

Also, since the hash structure includes key themselves (either explicitly via the prefix/suffix, or implicitly in the ordering of the branches), it isn't possible to re-order nodes in the trie or insert nodes other than at the place they were meant to be inserted. So for any given set of key/value pairs, there's exactly _one_ trie and thus root hash.

### Proving

Similar to Merkle-Trees, a proof of membership can be obtained by providing all neighbor nodes on the path to an element. This means that each proof stage can refer to up to 15 nodes. However, we need not to provide the entire nodes, but only the their respective hashes unless there's only one neighbor.

When nodes have exactly two branches (i.e. when a node has only one neighbor), we must also provide the prefix for that node if any. While unnecessary for verifying membership, it is needed to prove insertion and deletion. Indeed, in those cases, we must be able to reconstruct the trie without the element being proven, which in the case of nodes with 2 nodes, implies a change of structure and possibly, of prefix.

To build an intuition for this, let's visualize the different tranformation that one can operate on the trie. To make diagrams more readable, we will still include the nibbles corresponding to each branch next to the prefix. Prefixes will be shown between chevrons: `<` and `>`. And we'll also say _key_ when referring, in fact, to the hash digest of a key.

#### Adding a new child to a `Branch`

Let's consider two items `<aaaa> → 0` and `<aaab> → 1`, and a third one `<aaac> → 2` being inserted in the trie. The nodes all share a common prefix: `<aaa>`.

```
    <aaa>                         <aaa>
┌─────┴─────┐     =>    ┌───────────┼──────────┐
a<>         b<>         a<>         b<>        c<>
│           │           │           │          │
0           1           0           1          2
```

This is by far the simplest (and most common) scenario. This happens when the new child shares the same prefix as the other, but differs on a new nibble. This doesn't change anything regarding sub-tries under `a` and `b`, and simply changes the hash of the parent node in a straightforward manner.

- The root hash of the first trie is : `[ #0a, #0a, #0a, [ [[0]], [[1]] ] ]`;
- The root hash of the second trie is: `[ #0a, #0a, #0a, [ [[0]], [[1]], [[2]] ] ]`.

Here we can see how a proof for `2` would in fact only need to be `[0, 1]` as well as the length of the prefix (the nibbles themselves can be inferred from the key). If provided with those elements, it is easy to compute both roots. By simply re-hashing the proof itself, we obtain the root hash of the trie _without_ `<aaac> → 2`. But by including the value `2` in the proof, we obtain the root hash of the right-hand side trie _with_ `<aaac> → 2`.


#### Adding a new child to a `Leaf`

Let now consider a single item `<abaac> → 0` and a new item `<ababb> → 1`.

```
<abaac>              <aba>
   │       =>    ┌─────┴─────┐
   │             a<c>        b<b>
   │             │           │
   0             0           1
```

The transformation here is more involved. It requires finding the common prefix between both items, and creating a new _Branch_ node with that prefix. We then end up with two new leaf items with much shorter suffixes (`<c>` and `<b>`). Note that the parent node has a prefix of length 3, while child nodes each have suffixes of length 1. The remaining nibble is implied by the branching.

- The root hash of the first trie is:  `[ #00, #0a, #ba, #ac, [ 0 ] ]`;
- The root hash of the second trie is: `[ #0a, #0b, #0a, [ A, B ] ]`, where:
  - `A = [ #00, #0c, [[0]] ]`
  - `B = [ #00, #0b, [[1]] ]`

As you can see, going from the first to the second root hash is more complex than in the previous scenario. Which is why, in this particular context, the proof for `<ababb> → 1` must include the full neighboring node. Or in fact, it must include its prefix and its value's hash. Then, like in the previous case, we can compute the proof alone to obtain the root hash of the trie _without_ `<ababb> → 1`, and compute the proof with the element to find the other root hash.

#### Forking a `Branch` node

There's a third kind of transformation! This one is more subtle but occurs on certain occasions. We call it a _Fork_ and it occurs when a _Branch_ node prefix is being is split (or forked) due do a node sharing only part of it. Let's reconsider our first example: `<aaaa> → 0` and `<aaab> → 1`; but instead add a new item as `<accc> → 2`.

```
    <aaa>                          <a>
┌─────┴─────┐      =>       ┌───────┴──────┐
a<>         b<>             a<a>           c<cc>
│           │               │              │
│           │           ┌───┴────┐         │
│           │           a        b         │
│           │           │        │         │
0           1           0        1         2
```

Here we see how the trie is mostly preserved, but now nested under a new node with a shorter prefix. This type of change is particularly important to consider in insertion and deletion proofs. Again, let's look at the respective root hashes:

- The root hash of the first trie is: `[ #0a, #0a, #0a, [ [[0]], [[1]] ] ]`;
- The root hash of the second trie is: `[ #0a, [ A, C ] ]`, where:
  - `A = [ #0a, [ [[0]], [[1]] ] ]`
  - `C = [ #ff, #cc, [ 2 ] ]`

Here, we can see how having both `#0a` and `[ [[0]], [[1]] ]` is sufficient as proof for `<accc> → 2`; The first part of the key before `#0a` can be recovered from the key `<accc>`; and the second term can be used to compute the proof in both inclusion and exclusion.

[^1]: The actual formula used in the final implementation differs, as explained under [Forestry](#forestry).
