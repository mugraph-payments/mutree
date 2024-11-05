use std::{
    array::TryFromSliceError,
    num::{ParseIntError, TryFromIntError},
};

use thiserror::Error as ThisError;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, ThisError, PartialEq, Clone)]
pub enum Error {
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Empty key or value")]
    EmptyKeyOrValue,

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Element already exists")]
    ElementExists,

    #[error("Element does not exist")]
    ElementNotExists,

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Unknown error: {0}")]
    Unknown(String),

    #[error("Invalid length")]
    InvalidLength,
}

impl From<hex::FromHexError> for Error {
    #[coverage(off)]
    #[inline]
    fn from(error: hex::FromHexError) -> Self {
        Error::Deserialization(format!("hex error: {}", error))
    }
}

impl From<ParseIntError> for Error {
    #[coverage(off)]
    #[inline]
    fn from(error: ParseIntError) -> Self {
        Error::Deserialization(format!("parse int error: {}", error))
    }
}

impl From<TryFromIntError> for Error {
    #[coverage(off)]
    #[inline]
    fn from(error: TryFromIntError) -> Self {
        Error::Deserialization(format!("invalid number format: {}", error))
    }
}

impl From<TryFromSliceError> for Error {
    #[coverage(off)]
    #[inline]
    fn from(error: TryFromSliceError) -> Self {
        Error::Deserialization(format!("invalid slice format: {}", error))
    }
}
