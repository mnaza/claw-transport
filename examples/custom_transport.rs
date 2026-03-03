//! Implementing `Transport` for a custom backend.
//!
//! This example uses `tokio::sync::mpsc` channels as an in-memory
//! transport, showing how to implement the trait for any byte-stream.
//!
//! Run with: `cargo run --example custom_transport`

use claw_transport::Transport;

struct ChannelTransport {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl Transport for ChannelTransport {
    type Error = String;

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.tx
            .send(data.to_vec())
            .await
            .map_err(|e| e.to_string())
    }

    async fn recv(&mut self) -> Result<Vec<u8>, Self::Error> {
        self.rx.recv().await.ok_or_else(|| "channel closed".into())
    }

    fn is_connected(&self) -> bool {
        !self.tx.is_closed()
    }
}

/// Create a pair of connected transports.
fn channel_pair() -> (ChannelTransport, ChannelTransport) {
    let (tx_a, rx_b) = tokio::sync::mpsc::channel(16);
    let (tx_b, rx_a) = tokio::sync::mpsc::channel(16);
    (
        ChannelTransport { tx: tx_a, rx: rx_a },
        ChannelTransport { tx: tx_b, rx: rx_b },
    )
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, mut server) = channel_pair();

    println!("Client connected: {}", client.is_connected());
    println!("Server connected: {}", server.is_connected());

    // Client sends, server receives
    client.send(b"EHLO example.com\r\n").await?;
    let data = server.recv().await?;
    println!("Server got: {:?}", String::from_utf8_lossy(&data).trim());

    // Server replies
    server.send(b"250-Hello\r\n250 OK\r\n").await?;
    let reply = client.recv().await?;
    println!("Client got: {:?}", String::from_utf8_lossy(&reply).trim());

    // Drop server — client should detect disconnect
    drop(server);
    println!("After server drop, client connected: {}", client.is_connected());

    Ok(())
}
