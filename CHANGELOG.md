# Changelog

## 0.1.0

Initial release.

- `Transport` trait with async `send`/`recv`/`is_connected`
- `native` backend: tokio + rustls (TCP, implicit TLS, STARTTLS)
- `wasm` backend: epoxy-tls JS bridge via Wisp/WebSocket proxy
