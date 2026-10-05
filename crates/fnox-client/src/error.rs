//! The error every call to the daemon can fail with.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Why a call to the daemon failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum CallError {
    /// Connecting to the daemon's socket failed.
    SocketUnavailable { path: PathBuf, source: io::Error },
    /// The peer on the socket is not owned by the current user.
    PeerRejected(io::Error),
    /// Reading from or writing to the socket failed, including a timeout.
    Io(io::Error),
    /// The daemon closed the connection without replying, as one from an older
    /// fnox does for a request it cannot decode.
    EmptyResponse,
    /// A line exceeded [`MAX_LINE_BYTES`](crate::wire::MAX_LINE_BYTES).
    Oversize,
    /// The reply is not valid JSON of the expected shape.
    Decode(serde_json::Error),
    /// The platform has no daemon support.
    Unsupported,
    /// The daemon answered with an error.
    Daemon(String),
    /// The reply is well-formed but breaks the protocol.
    Protocol(&'static str),
}

impl CallError {
    /// Whether the socket does not exist or nothing listens on it.
    pub fn is_socket_missing(&self) -> bool {
        matches!(
            self,
            Self::SocketUnavailable { source, .. }
                if matches!(
                    source.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                )
        )
    }
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketUnavailable { path, source } => write!(
                f,
                "Failed to connect to fnox daemon at {}: {source}",
                path.display()
            ),
            Self::PeerRejected(source) => write!(f, "{source}"),
            Self::Io(source) => write!(f, "{source}"),
            Self::EmptyResponse => {
                write!(f, "fnox daemon closed the connection without a response")
            }
            Self::Oversize => write!(f, "fnox daemon line exceeds the size limit"),
            Self::Decode(source) => write!(f, "Failed to decode daemon response: {source}"),
            Self::Unsupported => write!(
                f,
                "fnox daemon is currently supported on Unix platforms only"
            ),
            Self::Daemon(message) => write!(f, "{message}"),
            Self::Protocol(what) => write!(f, "fnox daemon protocol violation: {what}"),
        }
    }
}

impl std::error::Error for CallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SocketUnavailable { source, .. } => Some(source),
            Self::PeerRejected(source) | Self::Io(source) => Some(source),
            Self::Decode(source) => Some(source),
            _ => None,
        }
    }
}
