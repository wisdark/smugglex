use colored::*;
use rustls::pki_types::ServerName;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::error::{Result, SmugglexError};

// Lazy static TLS configuration to avoid recreating for each request
static TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
});

static PROXY: OnceLock<String> = OnceLock::new();

/// Set global proxy URL
pub fn set_proxy(proxy_url: String) {
    let _ = PROXY.set(proxy_url);
}

/// Get configured proxy URL
fn get_proxy() -> Option<&'static str> {
    PROXY.get().map(|s| s.as_str())
}

/// A trait that combines AsyncRead and AsyncWrite.
trait ReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> ReadWrite for T {}

/// Creates a TCP or TLS stream, optionally through a proxy.
async fn get_stream(
    host: &str,
    port: u16,
    use_tls: bool,
) -> Result<Box<dyn ReadWrite + Unpin + Send>> {
    if let Some(proxy_url) = get_proxy() {
        get_stream_via_proxy(host, port, use_tls, proxy_url).await
    } else {
        get_stream_direct(host, port, use_tls).await
    }
}

/// Creates a direct TCP or TLS stream.
async fn get_stream_direct(
    host: &str,
    port: u16,
    use_tls: bool,
) -> Result<Box<dyn ReadWrite + Unpin + Send>> {
    let addr = format!("{}:{}", host, port);
    if use_tls {
        let connector = TlsConnector::from(Arc::clone(&TLS_CONFIG));
        let stream = TcpStream::connect(&addr).await?;
        let domain = ServerName::try_from(host.to_string())?;
        let tls_stream = connector.connect(domain, stream).await?;
        Ok(Box::new(tls_stream))
    } else {
        let stream = TcpStream::connect(&addr).await?;
        Ok(Box::new(stream))
    }
}

/// Creates a stream through an HTTP proxy using CONNECT tunnel.
async fn get_stream_via_proxy(
    host: &str,
    port: u16,
    use_tls: bool,
    proxy_url: &str,
) -> Result<Box<dyn ReadWrite + Unpin + Send>> {
    let proxy = Url::parse(proxy_url)
        .map_err(|e| SmugglexError::Io(format!("invalid proxy URL: {}", e)))?;
    let proxy_host = proxy
        .host_str()
        .ok_or_else(|| SmugglexError::Io("proxy URL has no host".to_string()))?;
    let proxy_port = proxy.port_or_known_default().unwrap_or(8080);
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

    let mut stream = TcpStream::connect(&proxy_addr).await.map_err(|e| {
        SmugglexError::Io(format!("failed to connect to proxy {}: {}", proxy_addr, e))
    })?;

    // Send CONNECT request to establish tunnel
    let connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        host, port, host, port
    );
    stream.write_all(connect_req.as_bytes()).await?;

    // Read proxy response
    let mut reader = BufReader::new(&mut stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;

    if !status_line.contains("200") {
        return Err(SmugglexError::Io(format!(
            "proxy CONNECT failed: {}",
            status_line.trim()
        )));
    }

    // Consume remaining headers
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Now we have a tunnel; do TLS handshake if needed
    if use_tls {
        let connector = TlsConnector::from(Arc::clone(&TLS_CONFIG));
        let domain = ServerName::try_from(host.to_string())?;
        let tls_stream = connector.connect(domain, stream).await?;
        Ok(Box::new(tls_stream))
    } else {
        Ok(Box::new(stream))
    }
}

/// Sends a raw HTTP request and returns the response and duration.
pub async fn send_request(
    host: &str,
    port: u16,
    request: &str,
    timeout: u64,
    verbose: bool,
    use_tls: bool,
) -> Result<(String, Duration)> {
    if verbose {
        println!("\n{}", "--- REQUEST ---".bold().blue());
        println!("{}", request.cyan());
    }

    let start = Instant::now();
    let timeout_dur = Duration::from_secs(timeout);

    let result = tokio::time::timeout(timeout_dur, async {
        let mut stream = get_stream(host, port, use_tls).await?;
        stream.write_all(request.as_bytes()).await?;

        let mut buf = Vec::with_capacity(8192);
        stream.read_to_end(&mut buf).await?;
        Ok::<Vec<u8>, crate::error::SmugglexError>(buf)
    })
    .await??;

    let response_str = match String::from_utf8(result) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    };

    let duration = start.elapsed();

    if verbose {
        println!("\n{}", "--- RESPONSE ---".bold().blue());
        println!("{}", response_str.white());
    }

    Ok((response_str, duration))
}
