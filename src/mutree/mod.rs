use redb::{backends::InMemoryBackend, Database};

use crate::prelude::*;

#[derive(Debug)]
pub struct Mutree<D: Digest> {
    pub trie: Trie<D>,
    pub database: Database,
}

impl<D: Digest> Mutree<D> {
    #[inline]
    pub fn new_in_memory() -> Result<Self, Error> {
        Ok(Self {
            trie: Trie::default(),
            database: Database::builder().create_with_backend(InMemoryBackend::new())?,
        })
    }
}
