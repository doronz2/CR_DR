//! Error types for the CR-DR reference implementation.

use thiserror::Error;

use crate::types::VoterId;

#[derive(Error, Debug)]
pub enum CrDrError {
    #[error("invalid election configuration: {0}")]
    InvalidConfig(String),

    #[error("duplicate voter id {0} in preprocessing/registration")]
    DuplicateVoter(VoterId),

    #[error("unknown voter id {0}")]
    UnknownVoter(VoterId),

    #[error("candidate {0} is not in the candidate set")]
    InvalidCandidate(u64),

    #[error("merkle error: {0}")]
    Merkle(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("threshold error: {0}")]
    Threshold(String),

    #[error("cut-and-choose audit failed: {0}")]
    CutAndChooseAudit(String),

    #[error("zk toolchain error: {0}")]
    ZkToolchain(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CrDrError>;
