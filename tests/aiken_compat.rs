use blake2::{digest::consts::U32, Blake2b};
use mucrdt::prelude::*;
use proptest::prelude::{
    prop::{collection::vec, sample::select},
    *,
};
use test_strategy::proptest;

type Blake2b256 = Blake2b<U32>;

// Bitcoin block test constants
const BITCOIN_845999_ROOT: &str = "225a4599b804ba53745538c83bfa699ecf8077201b61484c91171f5910a4a8f9";
const BITCOIN_845999_BLOCK: &str = "00000000000000000002d79d6d49c114e174c22b8d8432432ce45a05fd6a4d7b";
const BITCOIN_845999_BODY: &str = "f48fcceeac43babbf53a90023be2799a9d7617098b76ff229440ccbd1fd1b4d4";

const BITCOIN_845602_ROOT: &str = "225a4599b804ba53745538c83bfa699ecf8077201b61484c91171f5910a4a8f9";
const BITCOIN_845602_BLOCK: &str = "0000000000000000000261a131bf48cc5a19658ade8cfede99dc1c3933300d60";
const BITCOIN_845602_BODY: &str = "26f711634eb26999169bb927f629870938bb4b6b4d1a078b44a6b4ec54f9e8df";
const BITCOIN_845602_NEW_ROOT: &str =
    "507c03bc4a25fd1cac2b03592befa4225c5f3488022affa0ab059ca350de2353";

// Fruit trie root
const FRUIT_TRIE_ROOT: &str = "4acd78f345a686361df77541b2e0b533f53362e36620a1fdd3a13e0b61a3b078";

#[test]
fn test_verify_bitcoin_block_845999() {
    let trie = Forestry::<Blake2b256>::from_root(&hex::decode(BITCOIN_845999_ROOT).unwrap()).unwrap();
    let block_hash = hex::decode(BITCOIN_845999_BLOCK).unwrap();
    let block_body = hex::decode(BITCOIN_845999_BODY).unwrap();

    assert!(trie.verify(&block_hash, &block_body));
}

#[test]
fn test_insert_bitcoin_block_845602() {
    let mut trie =
        Forestry::<Blake2b256>::from_root(&hex::decode(BITCOIN_845602_ROOT).unwrap()).unwrap();
    let block_hash = hex::decode(BITCOIN_845602_BLOCK).unwrap();
    let block_body = hex::decode(BITCOIN_845602_BODY).unwrap();

    trie.insert(&block_hash, &block_body).unwrap();
    assert_eq!(hex::encode(trie.root.to_bytes()), BITCOIN_845602_NEW_ROOT);
}

// Fruit tests
const FRUITS: &[(&str, &str)] = &[
    ("apple[uid: 58]", "🍎"),
    ("apricot[uid: 0]", "🤷"),
    ("banana[uid: 218]", "🍌"),
    ("blueberry[uid: 0]", "🫐"),
    ("cherry[uid: 0]", "🍒"),
    ("coconut[uid: 0]", "🥥"),
    ("cranberry[uid: 0]", "🤷"),
    ("fig[uid: 68267]", "🤷"),
    ("grapefruit[uid: 0]", "🤷"),
    ("grapes[uid: 0]", "🍇"),
    ("guava[uid: 344]", "🤷"),
    ("kiwi[uid: 0]", "🥝"),
    ("kumquat[uid: 0]", "🤷"),
    ("lemon[uid: 0]", "🍋"),
    ("lime[uid: 0]", "🤷"),
    ("mango[uid: 0]", "🥭"),
    ("orange[uid: 0]", "🍊"),
    ("papaya[uid: 0]", "🤷"),
    ("passionfruit[uid: 0]", "🤷"),
    ("peach[uid: 0]", "🍑"),
    ("pear[uid: 0]", "🍐"),
    ("pineapple[uid: 12577]", "🍍"),
    ("plum[uid: 15492]", "🤷"),
    ("pomegranate[uid: 0]", "🤷"),
    ("raspberry[uid: 0]", "🤷"),
    ("strawberry[uid: 2532]", "🍓"),
    ("tangerine[uid: 11]", "🍊"),
    ("tomato[uid: 83468]", "🍅"),
    ("watermelon[uid: 0]", "🍉"),
    ("yuzu[uid: 0]", "🤷"),
];

#[test]
fn test_fruit_trie_verification() {
    let trie = Forestry::<Blake2b256>::from_root(&hex::decode(FRUIT_TRIE_ROOT).unwrap()).unwrap();

    for (fruit, emoji) in FRUITS {
        assert!(
            trie.verify(fruit.as_bytes(), emoji.as_bytes()),
            "Failed to verify {}: {}",
            fruit,
            emoji
        );
    }
}

#[proptest]
fn test_fruit_trie_mutations_fail(
    #[strategy(select(FRUITS.to_vec()))] pair: (&'static str, &'static str),
    #[strategy(vec(any::<u8>(), 1..32))] mutation: Vec<u8>,
) {
    let (fruit, emoji) = pair;

    let trie = Forestry::<Blake2b256>::from_root(&hex::decode(FRUIT_TRIE_ROOT)?)?;

    // Mutate the fruit name
    let mut mutated_fruit = fruit.as_bytes().to_vec();
    for (i, m) in mutation.iter().enumerate() {
        if i < mutated_fruit.len() {
            mutated_fruit[i] ^= m;
        }
    }

    // Verify the mutated fruit fails
    prop_assert!(!trie.verify(&mutated_fruit, emoji.as_bytes()));
}

#[proptest]
fn test_fruit_trie_value_mutations_fail(
    #[strategy(select(FRUITS.to_vec()))] pair: (&'static str, &'static str),
    #[strategy(vec(any::<u8>(), 1..32))] mutation: Vec<u8>,
) {
    let (fruit, emoji) = pair;
    let trie = Forestry::<Blake2b256>::from_root(&hex::decode(FRUIT_TRIE_ROOT)?)?;

    // Mutate the emoji value
    let mut mutated_emoji = emoji.as_bytes().to_vec();
    for (i, m) in mutation.iter().enumerate() {
        if i < mutated_emoji.len() {
            mutated_emoji[i] ^= m;
        }
    }

    // Verify the mutated value fails
    prop_assert!(!trie.verify(fruit.as_bytes(), &mutated_emoji));
}

#[proptest]
fn test_fruit_proof_consistency(
    #[strategy(select(FRUITS.to_vec()))] pair1: (&'static str, &'static str),
    #[strategy(select(FRUITS.to_vec()))] pair2: (&'static str, &'static str),
) {
    let (fruit1, emoji1) = pair1;
    let (fruit2, emoji2) = pair2;

    let mut trie = Forestry::<Blake2b256>::empty();

    // Insert first fruit
    trie.insert(fruit1.as_bytes(), emoji1.as_bytes()).unwrap();
    let root1 = trie.root;

    // Insert second fruit
    trie.insert(fruit2.as_bytes(), emoji2.as_bytes()).unwrap();
    let root2 = trie.root;

    if fruit1 != fruit2 {
        prop_assert_ne!(
            root1,
            root2,
            "Different fruits should produce different roots"
        );
    }

    // Verify both fruits are present
    prop_assert!(trie.verify(fruit1.as_bytes(), emoji1.as_bytes()));
    prop_assert!(trie.verify(fruit2.as_bytes(), emoji2.as_bytes()));
}
