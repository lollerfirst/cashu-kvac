use bitcoin::secp256k1;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No script in this was found")]
    NoScriptProvided,
    #[error("Cannot create proofs of empty")]
    EmptyList,
    #[error("Cannot instantiate SchnorrProver")]
    InvalidConfiguration,
    #[error("Cannot map hash to a valid point on the curve")]
    InvalidPoint,
    #[error("Wrong number of secrets for MintPrivateKey")]
    InvalidMintPrivateKey,
    /// Secp256k1 error
    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),
}
