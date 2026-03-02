//! tor-http-proxy — Minimal HTTP CONNECT proxy with SOCKS5 upstream.
//!
//! Accepts HTTP CONNECT requests and tunnels them through an upstream
//! SOCKS5 proxy (Arti). When the client sends a
//! `Proxy-Authorization: Basic <credentials>` header, the decoded
//! username and password are forwarded as SOCKS5 auth credentials,
//! giving each uniquely-credentialed request its own Tor circuit
//! (stream isolation per Tor's SOCKS extensions spec).
//!
//! Without a Proxy-Authorization header the request is forwarded
//! anonymously; Arti will assign it to a shared circuit.
//!
//! Configuration (environment variables):
//!   HTTP_PORT   — port to listen on        (default: 8118)
//!   SOCKS_PORT  — upstream Arti SOCKS5 port (default: 9150)

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::env;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_socks::tcp::Socks5Stream;

/// Maximum size of the HTTP request headers we will buffer before
/// rejecting the connection.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// How long to wait for a complete HTTP CONNECT request before
/// dropping the connection.  Prevents Slowloris-style resource
/// exhaustion when the proxy is exposed to untrusted clients.
const HEADER_TIMEOUT_SECS: u64 = 30;

/// SOCKS5 auth sub-negotiation (RFC 1929) encodes username and
/// password lengths as single bytes; values above 255 would be
/// silently truncated, potentially collapsing distinct circuit
/// identities into one.  Reject rather than silently degrade.
const MAX_CRED_LEN: usize = 255;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let http_port  = env::var("HTTP_PORT").unwrap_or_else(|_| "8118".into());
    let socks_port = env::var("SOCKS_PORT").unwrap_or_else(|_| "9150".into());
    let listen     = format!("0.0.0.0:{http_port}");
    let upstream   = format!("127.0.0.1:{socks_port}");

    let listener = TcpListener::bind(&listen).await?;
    eprintln!("tor-http-proxy: listening on {listen}  upstream SOCKS5 {upstream}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let upstream = upstream.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(stream, &upstream).await {
                eprintln!("tor-http-proxy: [{peer}] {e}");
            }
        });
    }
}

/// Drive one client connection; send a 502 on error so the client gets
/// a meaningful response rather than a bare TCP reset.
async fn serve(
    mut client: TcpStream,
    upstream: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match tunnel(&mut client, upstream).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            Err(e)
        }
    }
}

/// Parse CONNECT request, open SOCKS5 tunnel, splice bytes.
async fn tunnel(
    client: &mut TcpStream,
    upstream: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Enforce a deadline on header receipt to prevent slow-client
    // resource exhaustion.
    let (target, creds) = timeout(
        std::time::Duration::from_secs(HEADER_TIMEOUT_SECS),
        read_connect(client),
    )
    .await
    .unwrap_or_else(|_| Err("timed out waiting for CONNECT headers".into()))?;

    let mut server = match &creds {
        Some((user, pass)) => Socks5Stream::connect_with_password(
            upstream,
            target.as_str(),
            user.as_str(),
            pass.as_str(),
        )
        .await
        .map_err(|e| format!("SOCKS5 connect to {target}: {e}"))?
        .into_inner(),

        None => Socks5Stream::connect(upstream, target.as_str())
            .await
            .map_err(|e| format!("SOCKS5 connect to {target}: {e}"))?
            .into_inner(),
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    tokio::io::copy_bidirectional(client, &mut server).await?;
    Ok(())
}

/// Read HTTP request headers into a buffer, then parse the CONNECT line
/// and optional Proxy-Authorization header.
///
/// Returns `(target, Option<(username, password)>)`.
async fn read_connect(
    client: &mut TcpStream,
) -> Result<(String, Option<(String, String)>), Box<dyn std::error::Error + Send + Sync>> {
    // Accumulate bytes until the blank line that terminates HTTP headers.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];

    loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Err("client closed connection during request headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err("request headers too large".into());
        }
    }

    let text = std::str::from_utf8(&buf)?;
    let mut lines = text.lines();

    // First line must be "CONNECT host:port HTTP/1.x"
    let request_line = lines.next().ok_or("empty request")?;
    let mut words = request_line.splitn(3, ' ');
    let method = words.next().ok_or("missing method")?;
    if method != "CONNECT" {
        return Err(format!("only CONNECT is supported (got {method})").into());
    }
    let target = words.next().ok_or("missing target")?.to_string();

    // Scan remaining headers for Proxy-Authorization (case-insensitive).
    let mut credentials: Option<(String, String)> = None;
    for line in lines {
        if line.trim().is_empty() {
            break;
        }
        let Some(colon) = line.find(':') else { continue };
        let name  = line[..colon].trim();
        let value = line[colon + 1..].trim();

        if name.eq_ignore_ascii_case("Proxy-Authorization") {
            // value is "Basic <base64>"
            if let Some((scheme, b64)) = value.split_once(' ') {
                if scheme.eq_ignore_ascii_case("Basic") {
                    if let Ok(decoded) = BASE64.decode(b64.trim()) {
                        if let Ok(s) = String::from_utf8(decoded) {
                            if let Some((user, pass)) = s.split_once(':') {
                                // SOCKS5 RFC 1929: username and password are
                                // each length-prefixed with a single byte.
                                // Silently dropping over-length credentials
                                // would truncate them identically, collapsing
                                // distinct circuit identities.  Fail loudly.
                                if user.len() > MAX_CRED_LEN || pass.len() > MAX_CRED_LEN {
                                    return Err(format!(
                                        "Proxy-Authorization credentials exceed \
                                         SOCKS5 limit of {MAX_CRED_LEN} bytes"
                                    )
                                    .into());
                                }
                                credentials =
                                    Some((user.to_string(), pass.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok((target, credentials))
}
