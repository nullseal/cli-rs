//! Real WebSocket transports for use with `SocketIoClient`.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{
    connect_async,
    tungstenite::Message,
    MaybeTlsStream, WebSocketStream,
};
use tokio::net::TcpStream;
use futures_util::stream::{SplitSink, SplitStream};

use crate::client::WsTransport;

// ── TungsteniteWs ─────────────────────────────────────────────────────────────

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A real WebSocket transport backed by `tokio-tungstenite`.
pub struct TungsteniteWs {
    sink: SplitSink<WsStream, Message>,
    stream: SplitStream<WsStream>,
}

impl TungsteniteWs {
    /// Connect to a WebSocket URL (ws:// or wss://).
    pub async fn connect(url: &str) -> Result<Self> {
        let (ws, _) = connect_async(url).await?;
        let (sink, stream) = ws.split();
        Ok(Self { sink, stream })
    }

    /// Build an Engine.IO v4 WebSocket URL from an HTTP server URL.
    ///
    /// Converts `http://` → `ws://`, `https://` → `wss://`, and appends
    /// `<base-path>/socket.io/?EIO=4&transport=websocket`. Any base path on the
    /// server URL is preserved so the engine.io endpoint sits under the same
    /// reverse-proxy prefix as the REST API — e.g. `https://nullseal.com/core`
    /// → `wss://nullseal.com/core/socket.io/…`. A bare origin yields `/socket.io/`.
    pub fn build_url(server_url: &str) -> Result<String> {
        let mut url = url::Url::parse(server_url)?;
        match url.scheme() {
            "http" => url.set_scheme("ws").unwrap(),
            "https" => url.set_scheme("wss").unwrap(),
            _ => {}
        }
        let base = url.path().trim_end_matches('/').to_owned(); // "" or "/core"
        url.set_path(&format!("{base}/socket.io/"));
        url.query_pairs_mut()
            .append_pair("EIO", "4")
            .append_pair("transport", "websocket");
        Ok(url.to_string())
    }
}

impl WsTransport for TungsteniteWs {
    async fn send(&mut self, text: String) -> Result<()> {
        self.sink
            .send(Message::Text(text.into()))
            .await
            .map_err(|e| anyhow::anyhow!("ws send error: {e}"))
    }

    async fn recv(&mut self) -> Option<String> {
        loop {
            match self.stream.next().await {
                Some(Ok(Message::Text(t))) => return Some(t.to_string()),
                Some(Ok(Message::Close(_))) | None => return None,
                Some(Ok(_)) => continue, // skip binary/ping/pong at WS level
                Some(Err(_)) => return None,
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_http_to_ws() {
        let url = TungsteniteWs::build_url("http://localhost:3001").unwrap();
        assert!(url.starts_with("ws://localhost:3001/socket.io/"));
        assert!(url.contains("EIO=4"));
        assert!(url.contains("transport=websocket"));
    }

    #[test]
    fn build_url_https_to_wss() {
        let url = TungsteniteWs::build_url("https://api.example.com").unwrap();
        assert!(url.starts_with("wss://api.example.com/socket.io/"));
        assert!(url.contains("EIO=4"));
    }

    #[test]
    fn build_url_preserves_base_path() {
        // Core reverse-proxied under /core: the engine.io endpoint must stay under
        // the same prefix so it routes through the proxy, not the web app at root.
        let url = TungsteniteWs::build_url("https://nullseal.com/core").unwrap();
        assert!(url.starts_with("wss://nullseal.com/core/socket.io/"), "got {url}");
        assert!(url.contains("EIO=4"));
        assert!(url.contains("transport=websocket"));
        // Trailing slash on the base must not double up.
        let url2 = TungsteniteWs::build_url("https://nullseal.com/core/").unwrap();
        assert!(url2.starts_with("wss://nullseal.com/core/socket.io/"), "got {url2}");
    }
}
