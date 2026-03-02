//! health-probe — Verify the full proxy stack is working.
//!
//! Sends an HTTP CONNECT request to tor-http-proxy, which forwards it to
//! Arti's SOCKS5 port to open a circuit to an external host.  A
//! "200 Connection Established" response confirms that:
//!
//!   1. tor-http-proxy is accepting connections
//!   2. Arti has an active Tor circuit
//!   3. An exit node established the outbound TCP connection
//!
//! This replaces the curl-based Docker healthcheck, removing curl from the
//! runtime image and eliminating the associated attack surface.
//!
//! Exits 0 (healthy) or 1 (unhealthy).
//!
//! Environment:
//!   HTTP_PORT      — proxy port to check    (default: 8118)
//!   HEALTH_TIMEOUT — deadline in seconds    (default: 15)

use std::env;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const PROBE_HOST: &str = "check.torproject.org";
const PROBE_PORT: u16  = 443;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let http_port: u16 = env::var("HTTP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8118);

    let secs: u64 = env::var("HEALTH_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);

    match timeout(Duration::from_secs(secs), probe(http_port)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("unhealthy: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("unhealthy: timed out after {secs}s");
            std::process::exit(1);
        }
    }
}

/// Open a CONNECT tunnel to PROBE_HOST:PROBE_PORT through the HTTP proxy.
/// Returns Ok(()) when the proxy responds with 200, Err otherwise.
async fn probe(http_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(("127.0.0.1", http_port))
        .await
        .map_err(|e| format!("cannot reach HTTP proxy on port {http_port}: {e}"))?;

    let req = format!(
        "CONNECT {PROBE_HOST}:{PROBE_PORT} HTTP/1.1\r\n\
         Host: {PROBE_HOST}:{PROBE_PORT}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;

    // Read enough for the status line — "HTTP/1.1 200 Connection Established"
    // is 39 bytes; a 64-byte buffer is sufficient.
    let mut buf = [0u8; 64];
    let n    = stream.read(&mut buf).await?;
    let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");

    if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        Err(format!("unexpected response: {}", resp.trim_end()).into())
    }
}
