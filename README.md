# claw-transport

Async byte-stream transport trait with pluggable TLS backends.

Provides a `Transport` trait that abstracts over byte-stream
connections (TLS, plain TCP, WebSocket tunnels). No `Send` bound is
required, making it compatible with single-threaded runtimes like WASM.

Two built-in backends:

- `native` — tokio + rustls (direct TCP+TLS for native apps)
- `wasm` — epoxy-tls JS bridge (TLS through a Wisp/WebSocket proxy
  for browsers)

Both backends support implicit TLS and STARTTLS.

## Quick start

```toml
[dependencies]
# For native (tokio) apps:
claw-transport = { version = "0.1", features = ["native"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }

# For WASM/browser apps:
# claw-transport = { version = "0.1", features = ["wasm"] }
```

## The Transport trait

```rust
pub trait Transport {
    type Error: std::fmt::Display;

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    async fn recv(&mut self) -> Result<Vec<u8>, Self::Error>;
    fn is_connected(&self) -> bool;
}
```

Contract:

- `send` writes all provided bytes or returns an error.
- `recv` blocks until data is available. An empty `Vec` indicates a
  timeout. Connection closure returns an error.
- `is_connected` is a best-effort check; `true` does not guarantee
  the next `send` / `recv` will succeed.

## Examples

### Native: implicit TLS (IMAPS, SMTPS)

```rust
use claw_transport::native::TlsStream;
use claw_transport::Transport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect over TCP+TLS (port 993 = IMAPS)
    let mut stream = TlsStream::connect("imap.example.com", 993).await?;
    assert!(stream.is_tls());
    assert!(stream.is_connected());

    // Send an IMAP command
    stream.send(b"A001 LOGIN user pass\r\n").await?;

    // Receive the response
    let data = stream.recv().await?;
    println!("{}", String::from_utf8_lossy(&data));

    Ok(())
}
```

### Native: STARTTLS (SMTP port 587)

Connect with plain TCP, exchange EHLO/STARTTLS at the protocol level,
then upgrade to TLS:

```rust
use claw_transport::native::TlsStream;
use claw_transport::Transport;

async fn smtp_starttls() -> Result<(), Box<dyn std::error::Error>> {
    // Plain TCP connection (no TLS yet)
    let mut stream = TlsStream::connect_plain("smtp.example.com", 587).await?;
    assert!(!stream.is_tls());

    // Read server greeting
    let greeting = stream.recv().await?;
    println!("{}", String::from_utf8_lossy(&greeting));

    // Send EHLO
    stream.send(b"EHLO client.example.com\r\n").await?;
    let ehlo_resp = stream.recv().await?;

    // Send STARTTLS command
    stream.send(b"STARTTLS\r\n").await?;
    let starttls_resp = stream.recv().await?;

    // Upgrade to TLS
    stream.start_tls("smtp.example.com").await?;
    assert!(stream.is_tls());

    // Now all traffic is encrypted
    stream.send(b"EHLO client.example.com\r\n").await?;
    let encrypted_resp = stream.recv().await?;
    println!("{}", String::from_utf8_lossy(&encrypted_resp));

    Ok(())
}
```

### WASM: TLS through a Wisp proxy

In a browser/WASM environment, connections go through a WebSocket-based
Wisp proxy. The backend relays raw TCP bytes; TLS is handled entirely
in the browser via epoxy-tls.

```rust
use claw_transport::wasm::TlsStream;
use claw_transport::Transport;

async fn check_mail() -> Result<(), Box<dyn std::error::Error>> {
    // Connect through a Wisp proxy to the IMAP server
    let mut stream = TlsStream::connect(
        "ws://localhost:8080",   // Wisp proxy WebSocket URL
        "imap.example.com",      // target host
        993,                     // target port (IMAPS)
    ).await.map_err(|e| e.to_string())?;

    stream.send(b"A001 NOOP\r\n").await.map_err(|e| e.to_string())?;
    let data = stream.recv().await.map_err(|e| e.to_string())?;
    println!("{}", String::from_utf8_lossy(&data));

    Ok(())
}
```

### WASM: STARTTLS through a Wisp proxy

```rust
use claw_transport::wasm::TlsStream;
use claw_transport::Transport;

async fn smtp_starttls_wasm() -> Result<(), Box<dyn std::error::Error>> {
    // Plain TCP through the Wisp proxy (no TLS yet)
    let mut stream = TlsStream::connect_plain(
        "ws://localhost:8080",
        "smtp.example.com",
        587,
    ).await.map_err(|e| e.to_string())?;

    // ... EHLO, STARTTLS protocol exchange ...

    // Upgrade to TLS (handshake done by epoxy-tls in browser)
    stream.start_tls("smtp.example.com").await.map_err(|e| e.to_string())?;

    // All further traffic is encrypted end-to-end
    stream.send(b"EHLO client\r\n").await.map_err(|e| e.to_string())?;

    Ok(())
}
```

### WASM: certificate trust management

When a server has an invalid or expired certificate, the WASM backend
provides interactive trust management:

```rust
use claw_transport::wasm::TlsStream;

async fn connect_with_trust() {
    match TlsStream::connect("ws://localhost:8080", "mail.local", 993).await {
        Ok(stream) => { /* connected */ }
        Err(e) if e.is_cert_error() => {
            // Show error to user, let them decide
            if let Some(msg) = e.cert_error_message() {
                println!("Certificate error: {}", msg);
            }
            // User chose to trust — remember for this page session
            TlsStream::trust_host("mail.local", 993);
            // Retry
            let stream = TlsStream::connect("ws://localhost:8080", "mail.local", 993)
                .await
                .expect("should connect after trust");
        }
        Err(e) => { /* other error */ }
    }
}
```

### Custom transport

Implement `Transport` for any byte-stream:

```rust
use claw_transport::Transport;

struct MyTransport { /* ... */ }

impl Transport for MyTransport {
    type Error = std::io::Error;

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        // write all bytes to peer
        todo!()
    }

    async fn recv(&mut self) -> Result<Vec<u8>, Self::Error> {
        // read available bytes; return Ok(vec![]) on timeout
        todo!()
    }

    fn is_connected(&self) -> bool {
        todo!()
    }
}
```

Then use it with any protocol client (claw-imap, claw-smtp):

```rust
use claw_imap::ImapClient;

async fn example(transport: MyTransport) {
    let mut client = ImapClient::new(transport).await.unwrap();
    client.login("user", "pass").await.unwrap();
    // ...
}
```

## API overview

### Transport trait

| Method | Description |
|---|---|
| `send(data)` | Write all bytes to the remote peer |
| `recv()` | Read available bytes (empty Vec on timeout) |
| `is_connected()` | Best-effort liveness check |

### native::TlsStream

| Method | Description |
|---|---|
| `connect()` | TCP+TLS (implicit TLS, 30s timeout) |
| `connect_plain()` | Plain TCP (for STARTTLS, 30s timeout) |
| `start_tls()` | Upgrade plain TCP to TLS (30s timeout) |
| `is_tls()` | Check if currently using TLS |
| `is_connected()` | Connection liveness check |

### wasm::TlsStream

| Method | Description |
|---|---|
| `connect()` | TLS through Wisp proxy |
| `connect_plain()` | Plain TCP through Wisp proxy (for STARTTLS) |
| `start_tls()` | Upgrade to TLS (epoxy-tls/forge.js handshake) |
| `trust_host()` | Bypass cert validation for a host (page session) |
| `is_host_trusted()` | Check if a host is trusted |
| `is_connected()` | Connection liveness check |

## Timeouts

All blocking operations have a 30-second timeout:

- TCP connect (native)
- TLS handshake (native)
- Recv / wait-for-data (both native and WASM)

On timeout, `recv` returns `Ok(Vec::new())` per the `Transport` contract.
Connect and handshake timeouts return `TlsError::Timeout`.

## Features

| Feature | Dependencies | Target |
|---|---|---|
| `native` | tokio, tokio-rustls, webpki-roots | Native apps |
| `wasm` | wasm-bindgen, js-sys | Browsers |

Both features are off by default. Enable exactly one for your target
platform.

## License

MIT
