//! TLS transport via epoxy-tls JS bridge (for browser/WASM).
//!
//! The epoxy-tls library handles both the Wisp protocol and TLS internally,
//! providing end-to-end encryption with TLS 1.2/1.3 support. Connections
//! are tunnelled through a WebSocket-based Wisp proxy.

use js_sys::{Promise, Uint8Array};
use thiserror::Error;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Default timeout for [`Transport::recv`] in milliseconds.
///
/// Set to 30 seconds because some mail servers delay their greeting
/// while performing reverse DNS lookups or greylisting checks.
const DEFAULT_RECV_TIMEOUT_MS: u32 = 30_000;

/// TLS transport errors.
#[derive(Debug, Clone, Error)]
pub enum TlsError {
    /// TCP or WebSocket connection could not be established.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Data could not be sent over the connection.
    #[error("Send failed: {0}")]
    SendFailed(String),

    /// Data could not be received from the connection.
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    /// TLS protocol error after handshake.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Server certificate validation failed.
    ///
    /// Call [`TlsStream::trust_host`] and retry to accept the certificate.
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// Error from the JavaScript runtime.
    #[error("JavaScript error: {0}")]
    Js(String),

    /// Operation attempted on a closed connection.
    #[error("Not connected")]
    NotConnected,
}

impl TlsError {
    /// Returns `true` if this is a certificate validation error.
    pub fn is_cert_error(&self) -> bool {
        matches!(self, TlsError::CertificateError(_))
    }

    /// Returns the certificate error message, if this is a certificate error.
    pub fn cert_error_message(&self) -> Option<&str> {
        match self {
            TlsError::CertificateError(msg) => Some(msg),
            _ => None,
        }
    }
}

impl From<JsValue> for TlsError {
    fn from(value: JsValue) -> Self {
        let msg = value
            .as_string()
            .unwrap_or_else(|| format!("{:?}", value));
        TlsError::Js(msg)
    }
}

// JavaScript bindings to TlsBridge (epoxy-based)
#[wasm_bindgen]
extern "C" {
    type TlsConnection;

    #[wasm_bindgen(js_namespace = ["window", "TlsBridge"], js_name = createConnection)]
    fn create_tls_connection() -> TlsConnection;

    #[wasm_bindgen(method)]
    fn connect(this: &TlsConnection, wisp_url: &str, hostname: &str, port: u16) -> Promise;

    #[wasm_bindgen(method, js_name = connectPlain)]
    fn connect_plain(this: &TlsConnection, wisp_url: &str, hostname: &str, port: u16) -> Promise;

    #[wasm_bindgen(method, js_name = startTls)]
    fn start_tls(this: &TlsConnection, hostname: &str) -> Promise;

    #[wasm_bindgen(method)]
    fn send(this: &TlsConnection, data: &Uint8Array) -> Promise;

    #[wasm_bindgen(method)]
    fn recv(this: &TlsConnection) -> Option<Uint8Array>;

    #[wasm_bindgen(method, js_name = waitForData)]
    fn wait_for_data(this: &TlsConnection, timeout_ms: u32) -> Promise;

    #[wasm_bindgen(method, js_name = isConnected)]
    fn is_connected(this: &TlsConnection) -> bool;

    #[wasm_bindgen(method, js_name = hasError)]
    fn has_error(this: &TlsConnection) -> bool;

    #[wasm_bindgen(method, js_name = getError)]
    fn get_error(this: &TlsConnection) -> Option<String>;

    #[wasm_bindgen(method, js_name = hasCertError)]
    fn has_cert_error(this: &TlsConnection) -> bool;

    #[wasm_bindgen(method, js_name = getCertError)]
    fn get_cert_error(this: &TlsConnection) -> Option<String>;

    #[wasm_bindgen(method)]
    fn close(this: &TlsConnection);
}

// Static trust management functions
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "TlsBridge", "TlsConnection"], js_name = trustHost)]
    fn js_trust_host(hostname: &str, port: u16);

    #[wasm_bindgen(js_namespace = ["window", "TlsBridge", "TlsConnection"], js_name = isHostTrusted)]
    fn js_is_host_trusted(hostname: &str, port: u16) -> bool;
}

/// TLS connection via epoxy-tls JS bridge.
///
/// Handles Wisp protocol tunnelling and TLS internally. The connection
/// goes: Browser → WebSocket → Wisp Proxy → TCP → Mail Server (with
/// end-to-end TLS).
pub struct TlsStream {
    tls: TlsConnection,
}

impl TlsStream {
    /// Connect to a remote host through a Wisp proxy.
    ///
    /// # Arguments
    ///
    /// * `backend_url` — WebSocket URL of the Wisp proxy (e.g., `"ws://localhost:8080"`)
    /// * `host` — Target hostname for the TLS connection
    /// * `port` — Target port for the TLS connection
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::CertificateError`] if the server's certificate is
    /// invalid. Call [`trust_host`](Self::trust_host) and retry to accept it.
    pub async fn connect(
        backend_url: &str,
        host: &str,
        port: u16,
    ) -> Result<Self, TlsError> {
        let tls = create_tls_connection();

        let connect_promise = tls.connect(backend_url, host, port);
        let result = JsFuture::from(connect_promise).await?;

        let success = result.as_bool().unwrap_or(false);
        if !success {
            if tls.has_cert_error() {
                let msg = tls
                    .get_cert_error()
                    .unwrap_or_else(|| "Certificate validation failed".to_string());
                return Err(TlsError::CertificateError(msg));
            }

            let msg = tls
                .get_error()
                .unwrap_or_else(|| "Connection failed".to_string());
            return Err(TlsError::ConnectionFailed(msg));
        }

        Ok(Self { tls })
    }

    /// Connect to a remote host through a Wisp proxy using plain TCP (no TLS).
    ///
    /// Used for STARTTLS flows where the connection starts unencrypted and
    /// TLS is negotiated at the application protocol level. Call
    /// [`start_tls`](Self::start_tls) after the protocol-level STARTTLS
    /// command to upgrade to TLS.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::ConnectionFailed`] if the TCP connection cannot
    /// be established.
    pub async fn connect_plain(
        backend_url: &str,
        host: &str,
        port: u16,
    ) -> Result<Self, TlsError> {
        let tls = create_tls_connection();

        let connect_promise = tls.connect_plain(backend_url, host, port);
        let result = JsFuture::from(connect_promise).await?;

        let success = result.as_bool().unwrap_or(false);
        if !success {
            let msg = tls
                .get_error()
                .unwrap_or_else(|| "Plain TCP connection failed".to_string());
            return Err(TlsError::ConnectionFailed(msg));
        }

        Ok(Self { tls })
    }

    /// Upgrade this plain TCP connection to TLS (STARTTLS).
    ///
    /// Must be called on a connection created with [`connect_plain`](Self::connect_plain)
    /// after the application protocol has negotiated STARTTLS. Uses forge.js
    /// for the TLS handshake over the existing TCP stream.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Tls`] if the TLS handshake fails.
    /// Returns [`TlsError::NotConnected`] if the connection is closed.
    pub async fn start_tls(&self, hostname: &str) -> Result<(), TlsError> {
        if !self.tls.is_connected() {
            return Err(TlsError::NotConnected);
        }

        let promise = self.tls.start_tls(hostname);
        JsFuture::from(promise)
            .await
            .map_err(|e| {
                let msg = e
                    .as_string()
                    .unwrap_or_else(|| format!("{:?}", e));
                TlsError::Tls(format!("STARTTLS handshake failed: {}", msg))
            })?;

        Ok(())
    }

    /// Mark a host as trusted, bypassing certificate validation on future connects.
    ///
    /// This persists for the lifetime of the page (not across reloads).
    pub fn trust_host(host: &str, port: u16) {
        js_trust_host(host, port);
    }

    /// Check whether a host has been marked as trusted.
    pub fn is_host_trusted(host: &str, port: u16) -> bool {
        js_is_host_trusted(host, port)
    }
}

impl crate::Transport for TlsStream {
    type Error = TlsError;

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        if !self.tls.is_connected() {
            return Err(TlsError::NotConnected);
        }

        let js_array = Uint8Array::new_with_length(data.len() as u32);
        js_array.copy_from(data);

        let send_promise = self.tls.send(&js_array);
        JsFuture::from(send_promise)
            .await
            .map_err(|e| TlsError::SendFailed(format!("{:?}", e)))?;

        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<u8>, Self::Error> {
        if !self.tls.is_connected() {
            return Err(TlsError::NotConnected);
        }

        // Return already-buffered data immediately
        if let Some(data) = self.tls.recv() {
            return Ok(data.to_vec());
        }

        // Wait for data with timeout
        let wait_promise = self.tls.wait_for_data(DEFAULT_RECV_TIMEOUT_MS);
        let got_data = JsFuture::from(wait_promise)
            .await
            .map_err(|e| TlsError::ReceiveFailed(format!("{:?}", e)))?;

        if !got_data.as_bool().unwrap_or(false) {
            // Timeout — return empty per Transport contract
            return Ok(Vec::new());
        }

        // Check for errors that occurred while waiting
        if self.tls.has_error() {
            let err = self
                .tls
                .get_error()
                .unwrap_or_else(|| "Unknown TLS error".to_string());
            return Err(TlsError::Tls(err));
        }

        if let Some(data) = self.tls.recv() {
            Ok(data.to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    fn is_connected(&self) -> bool {
        self.tls.is_connected()
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        self.tls.close();
    }
}
