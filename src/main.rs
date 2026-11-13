use dokploy_mcp::{Config, app};
use std::io::{Read, Write};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8787".into());
    if std::env::args().any(|a| a == "--healthcheck") {
        let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut response = [0; 64];
        let n = stream.read(&mut response)?;
        if !response[..n].starts_with(b"HTTP/1.1 200") {
            return Err("health check failed".into());
        }
        return Ok(());
    }
    let router = app(Config::from_env()?)?;
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    eprintln!("Dokploy MCP listening on {port}");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            #[cfg(unix)]
            {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .unwrap();
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            }
            #[cfg(not(unix))]
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
