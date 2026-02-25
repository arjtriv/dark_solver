use thiserror::Error;

pub type Result<T> = std::result::Result<T, DarkError>;

#[derive(Debug, Error)]
pub enum DarkError {
    #[error("math error: {0}")]
    Math(#[from] Z3Error),
    #[error("network error: {0}")]
    Net(#[from] RpcError),
    #[error("logic error: {0}")]
    Logic(#[from] InvariantWaitError),
}

#[derive(Debug, Error)]
pub enum Z3Error {
    #[error("z3 operation failed: {0}")]
    Operation(String),
    #[error("arithmetic overflow guard violated: {0}")]
    Overflow(String),
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("invalid URL `{url}`: {reason}")]
    InvalidUrl { url: String, reason: String },
    #[error("transport failure: {0}")]
    Transport(String),
    #[error("public RPC endpoint rejected for private relay safety: {0}")]
    PublicRpcEndpoint(String),
    #[error("bundle handshake rejected: {0}")]
    BundleHandshakeRejected(String),
}

#[derive(Debug, Error)]
pub enum InvariantWaitError {
    #[error("missing required configuration: {0}")]
    MissingConfig(String),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("invariant failed: {0}")]
    Invariant(String),
    #[error("invariant wait timed out after {waited_ms}ms: {context}")]
    Timeout { waited_ms: u64, context: String },
}

pub type MathError = Z3Error;
pub type NetError = RpcError;
pub type LogicError = InvariantWaitError;
