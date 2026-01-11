use thiserror::Error;

#[derive(Error, Debug)]
pub enum SerenoError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Rule not found: {0}")]
    RuleNotFound(String),

    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("Invalid rule condition: {0}")]
    InvalidCondition(String),

    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(#[from] regex::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SerenoError>;
