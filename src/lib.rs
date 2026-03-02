//! Async byte-stream transport trait with pluggable TLS backends.
//!
//! Provides a [`Transport`] trait that abstracts over byte-stream
//! connections (TLS, plain TCP, WebSocket tunnels, etc.).
//!
//! No `Send` bound is required, making this compatible with single-threaded
//! runtimes like WASM.
//!
//! # Features
//!
//! - `wasm` — `wasm::TlsStream`: TLS via epoxy-tls JS bridge (for browser/WASM).
//!   Connects through a Wisp proxy over WebSocket.
//! - `native` — `native::TlsStream`: TLS via tokio + rustls (for native apps).
//!   Direct TCP+TLS connection.

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "native")]
pub mod native;

/// Async byte-stream transport.
///
/// The transport must already be connected when passed to a protocol client.
/// Connection setup (TLS handshake, etc.) is the caller's responsibility.
///
/// Uses native `async fn` in trait (Rust 1.75+) without `Send` bounds,
/// for WASM single-threaded runtime compatibility.
///
/// # Contract
///
/// - [`send`](Transport::send) writes all provided bytes or returns an error.
/// - [`recv`](Transport::recv) blocks until data is available. An empty `Vec`
///   indicates a timeout; connection closure should return an error.
/// - [`is_connected`](Transport::is_connected) returns `true` if the transport
///   believes the connection is alive. A `true` return does not guarantee the
///   next `send`/`recv` will succeed.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// The error type for transport operations.
    type Error: std::fmt::Display;

    /// Send all bytes to the remote peer.
    ///
    /// Returns `Ok(())` when all data has been written, or an error
    /// if the write fails.
    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Receive data from the remote peer.
    ///
    /// Blocks until at least some data is available. Returns the received
    /// bytes. An empty `Vec` indicates a timeout (no data within the
    /// implementation's timeout window). Connection closure or I/O errors
    /// should be reported as `Err`, not as an empty `Vec`.
    async fn recv(&mut self) -> Result<Vec<u8>, Self::Error>;

    /// Check if the transport believes the connection is still alive.
    ///
    /// This is a best-effort check. A return value of `true` does not
    /// guarantee that the next `send` or `recv` will succeed.
    fn is_connected(&self) -> bool;
}
