//! Local TCP echo demo using `native::TlsStream`.
//!
//! Starts a local TCP echo server, connects with `connect_plain`,
//! sends a message, and prints the echoed response.
//!
//! Run with: `cargo run --example echo --features native`

use claw_transport::native::TlsStream;
use claw_transport::Transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start a local echo server
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    println!("Echo server listening on 127.0.0.1:{port}");

    tokio::spawn(async move {
        let (mut socket, addr) = listener.accept().await.unwrap();
        println!("Server: accepted connection from {addr}");
        let mut buf = vec![0u8; 4096];
        loop {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            socket.write_all(&buf[..n]).await.unwrap();
        }
    });

    // Connect using claw-transport
    let mut stream = TlsStream::connect_plain("127.0.0.1", port).await?;
    println!("Connected: is_tls={}, is_connected={}", stream.is_tls(), stream.is_connected());

    // Send and receive
    let message = b"Hello from claw-transport!\r\n";
    stream.send(message).await?;
    println!("Sent: {:?}", String::from_utf8_lossy(message).trim());

    let response = stream.recv().await?;
    println!("Received: {:?}", String::from_utf8_lossy(&response).trim());

    assert_eq!(&response, message);
    println!("Echo verified.");

    Ok(())
}
