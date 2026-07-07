use thiserror::Error;

#[derive(Debug, Error)]
pub enum AggiosError {
    #[error("domain error: {0}")]
    Domain(String),
    #[error("EPA adapter error: {0}")]
    Epa(String),
    #[error("registration error: {0}")]
    Registration(String),
    #[error("tally error: {0}")]
    Tally(String),
    #[error("verification error: {0}")]
    Verification(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("benchmark error: {0}")]
    Benchmark(String),
}

pub type Result<T> = std::result::Result<T, AggiosError>;
