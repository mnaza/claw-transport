# Changelog

## 0.1.2

- Switch README from org-mode to Markdown (crates.io rendering)
- Add `homepage` and `documentation` metadata

## 0.1.1

- Add examples (`echo`, `custom_transport`)
- Add CI/CD workflows (fmt, clippy, test, WASM check, MSRV, release)
- Add `#[deny(missing_docs)]` lint
- Update `webpki-roots` from 0.26 to 1.0
- Add LICENSE file, CHANGELOG, author metadata

## 0.1.0

Initial release.

- `Transport` trait with async `send`/`recv`/`is_connected`
- `native` backend: tokio + rustls (TCP, implicit TLS, STARTTLS)
- `wasm` backend: epoxy-tls JS bridge via Wisp/WebSocket proxy
