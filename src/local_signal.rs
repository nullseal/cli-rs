/// TCP-based signaling for fully local transfers (no server needed).
///
/// Protocol: newline-delimited JSON over a single TCP connection.
/// Message types: offer, answer, ice, ready, error.

use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

// ── SignalServer (sender side) ────────────────────────────────────────────────

pub struct SignalServer {
    listener: TcpListener,
    addr: std::net::SocketAddr,
}

impl SignalServer {
    /// Bind on an ephemeral port on all interfaces. Returns the bound address.
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let addr = listener.local_addr()?;
        Ok(SignalServer { listener, addr })
    }

    /// Bind on a specific IP with an ephemeral port.
    /// Use this when the advertised IP must match the listening interface.
    pub async fn bind_to(ip: &str) -> Result<Self> {
        let listener = TcpListener::bind(format!("{ip}:0")).await?;
        let addr = listener.local_addr()?;
        Ok(SignalServer { listener, addr })
    }

    /// Bind to an exact address (ip:port). Fails if the port is already in use.
    pub async fn bind_addr(addr: &str) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        Ok(SignalServer { listener, addr })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Accept exactly one connection and return a duplex channel.
    pub async fn accept(self) -> Result<SignalChannel> {
        let (stream, _peer) = self.listener.accept().await?;
        Ok(SignalChannel::new(stream))
    }
}

// ── SignalClient (receiver side) ───────────────────────────────────────────────

pub struct SignalClient;

impl SignalClient {
    /// Connect to the sender's signaling server.
    pub async fn connect(addr: &str) -> Result<SignalChannel> {
        let stream = TcpStream::connect(addr).await?;
        Ok(SignalChannel::new(stream))
    }
}

// ── SignalChannel (shared by both sides) ──────────────────────────────────────

pub struct SignalChannel {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
}

impl SignalChannel {
    fn new(stream: TcpStream) -> Self {
        let (read, write) = tokio::io::split(stream);
        SignalChannel {
            reader: BufReader::new(read),
            writer: write,
        }
    }

    /// Send a JSON message (newline-delimited).
    pub async fn send(&mut self, msg: &Value) -> Result<()> {
        let mut line = serde_json::to_string(msg)?;
        line.push('\n');
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Receive the next JSON message. Returns None on EOF.
    pub async fn recv(&mut self) -> Result<Option<Value>> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        let v: Value = serde_json::from_str(line.trim())?;
        Ok(Some(v))
    }

    /// Receive the next message, bail on EOF.
    pub async fn recv_or_bail(&mut self) -> Result<Value> {
        self.recv()
            .await?
            .ok_or_else(|| anyhow::anyhow!("signaling connection closed"))
    }

    pub async fn send_offer(&mut self, sdp: Value) -> Result<()> {
        self.send(&serde_json::json!({"type": "offer", "sdp": sdp})).await
    }

    pub async fn send_answer(&mut self, sdp: Value) -> Result<()> {
        self.send(&serde_json::json!({"type": "answer", "sdp": sdp})).await
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_returns_ephemeral_port() {
        let server = SignalServer::bind().await.unwrap();
        assert!(server.port() > 0);
    }

    #[tokio::test]
    async fn bind_to_loopback() {
        let server = SignalServer::bind_to("127.0.0.1").await.unwrap();
        assert!(server.port() > 0);
    }

    #[tokio::test]
    async fn bind_addr_specific_port() {
        let server = SignalServer::bind_addr("127.0.0.1:0").await.unwrap();
        assert!(server.port() > 0);
    }

    #[tokio::test]
    async fn bind_addr_respects_explicit_port() {
        // Bind to a specific port and verify it's actually used
        let server = SignalServer::bind_addr("127.0.0.1:19876").await.unwrap();
        assert_eq!(server.port(), 19876);
    }
}
