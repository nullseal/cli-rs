//! Pure Engine.IO + Socket.IO v4 frame codec.
//!
//! No I/O, no async — just encode/decode functions and types.

use serde_json::Value;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Engine.IO open handshake payload.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenHandshake {
    pub sid: String,
    pub ping_interval: u64,
    pub ping_timeout: u64,
}

/// A parsed frame from the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// Engine.IO open (`0{...}`)
    Open(OpenHandshake),
    /// Engine.IO ping (`2`)
    Ping,
    /// Engine.IO pong (`3`)
    Pong,
    /// Socket.IO namespace connect ack (`40/ns,{...}`)
    NamespaceAck { sid: String },
    /// Socket.IO namespace connect error (`44/ns,{...}`)
    ConnectError(String),
    /// Socket.IO namespace disconnect (`41/ns`)
    Disconnect,
    /// Socket.IO event (`42/ns,[event, payload]`)
    Event { event: String, payload: Value },
    /// Anything else we don't specifically handle
    Other(String),
}

// ── Parsing ───────────────────────────────────────────────────────────────────

/// Parse an Engine.IO open frame (`0{...}`).
pub fn parse_open(payload: &str) -> Option<OpenHandshake> {
    let json_str = payload.strip_prefix('0')?;
    let v: Value = serde_json::from_str(json_str).ok()?;
    Some(OpenHandshake {
        sid: v["sid"].as_str()?.to_owned(),
        ping_interval: v["pingInterval"].as_u64().unwrap_or(25000),
        ping_timeout: v["pingTimeout"].as_u64().unwrap_or(20000),
    })
}

/// Parse a namespace connect ack for a given namespace.
/// Returns the namespace sid on success, or an error message on connect error.
pub fn parse_namespace_ack(text: &str, ns: &str) -> Result<String, String> {
    let ns = ns.trim_start_matches('/');
    let ack_prefix = format!("40/{ns},");
    let err_prefix = format!("44/{ns},");

    if let Some(json_str) = text.strip_prefix(&ack_prefix) {
        let v: Value = serde_json::from_str(json_str)
            .map_err(|e| format!("invalid ack JSON: {e}"))?;
        let sid = v["sid"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        Ok(sid)
    } else if let Some(json_str) = text.strip_prefix(&err_prefix) {
        Err(format!("connect error: {json_str}"))
    } else {
        Err(format!("unexpected frame: {text}"))
    }
}

/// Parse any incoming text frame for a given namespace into a `Frame`.
pub fn parse_frame(text: &str, ns: &str) -> Frame {
    let ns = ns.trim_start_matches('/');
    // Engine.IO level
    if text == "2" {
        return Frame::Ping;
    }
    if text == "3" {
        return Frame::Pong;
    }
    if text.starts_with('0') {
        if let Some(h) = parse_open(text) {
            return Frame::Open(h);
        }
    }

    // Socket.IO namespace ack: 40/ns,{...}
    let ack_prefix = format!("40/{ns},");
    if let Some(json_str) = text.strip_prefix(&ack_prefix) {
        let sid = serde_json::from_str::<Value>(json_str)
            .ok()
            .and_then(|v| v["sid"].as_str().map(|s| s.to_owned()))
            .unwrap_or_default();
        return Frame::NamespaceAck { sid };
    }

    // Socket.IO connect error: 44/ns,{...}
    let err_prefix = format!("44/{ns},");
    if let Some(json_str) = text.strip_prefix(&err_prefix) {
        return Frame::ConnectError(json_str.to_owned());
    }

    // Socket.IO namespace disconnect: 41/ns
    let disc_prefix = format!("41/{ns}");
    if text.starts_with(&disc_prefix) {
        return Frame::Disconnect;
    }

    // Socket.IO event: 42/ns,[event, payload]
    let event_prefix = format!("42/{ns},");
    if let Some(json_str) = text.strip_prefix(&event_prefix) {
        if let Ok(arr) = serde_json::from_str::<Vec<Value>>(json_str) {
            if !arr.is_empty() {
                let event = arr[0].as_str().unwrap_or("").to_owned();
                let payload = arr.get(1).cloned().unwrap_or(Value::Null);
                return Frame::Event { event, payload };
            }
        }
    }

    Frame::Other(text.to_owned())
}

// ── Encoding ──────────────────────────────────────────────────────────────────

/// Encode a namespace connect request: `40/ns,`
pub fn encode_namespace_connect(ns: &str) -> String {
    let ns = ns.trim_start_matches('/');
    format!("40/{ns},")
}

/// Encode a Socket.IO event for a given namespace: `42/ns,["event",payload]`
pub fn encode_event(ns: &str, event: &str, payload: &Value) -> String {
    let ns = ns.trim_start_matches('/');
    let arr = serde_json::json!([event, payload]);
    format!("42/{ns},{arr}")
}

/// Encode a namespace disconnect: `41/ns,`
pub fn encode_disconnect(ns: &str) -> String {
    let ns = ns.trim_start_matches('/');
    format!("41/{ns},")
}

/// Engine.IO pong frame.
pub const PONG: &str = "3";

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Golden vectors: Open ──────────────────────────────────────────────────

    #[test]
    fn parse_open_valid() {
        let raw = r#"0{"sid":"abc123","upgrades":[],"pingInterval":25000,"pingTimeout":20000,"maxPayload":100000}"#;
        let h = parse_open(raw).unwrap();
        assert_eq!(h.sid, "abc123");
        assert_eq!(h.ping_interval, 25000);
        assert_eq!(h.ping_timeout, 20000);
    }

    #[test]
    fn parse_open_missing_prefix_returns_none() {
        assert!(parse_open(r#"{"sid":"x"}"#).is_none());
    }

    // ── Golden vectors: Ping / Pong ──────────────────────────────────────────

    #[test]
    fn parse_frame_ping() {
        assert_eq!(parse_frame("2", "p2p"), Frame::Ping);
    }

    #[test]
    fn parse_frame_pong() {
        assert_eq!(parse_frame("3", "p2p"), Frame::Pong);
    }

    // ── Golden vectors: Namespace ack ────────────────────────────────────────

    #[test]
    fn parse_frame_namespace_ack() {
        let f = parse_frame(r#"40/chat,{"sid":"nsid-123"}"#, "chat");
        assert_eq!(f, Frame::NamespaceAck { sid: "nsid-123".into() });
    }

    #[test]
    fn parse_namespace_ack_fn_ok() {
        let sid = parse_namespace_ack(r#"40/p2p,{"sid":"ns1"}"#, "p2p").unwrap();
        assert_eq!(sid, "ns1");
    }

    #[test]
    fn parse_namespace_ack_fn_error() {
        let err = parse_namespace_ack(r#"44/p2p,{"message":"unauthorized"}"#, "p2p").unwrap_err();
        assert!(err.contains("connect error"));
    }

    // ── Golden vectors: Connect error ────────────────────────────────────────

    #[test]
    fn parse_frame_connect_error() {
        let f = parse_frame(r#"44/p2p,{"message":"forbidden"}"#, "p2p");
        assert_eq!(f, Frame::ConnectError(r#"{"message":"forbidden"}"#.into()));
    }

    // ── Golden vectors: Disconnect ───────────────────────────────────────────

    #[test]
    fn parse_frame_disconnect() {
        let f = parse_frame("41/p2p", "p2p");
        assert_eq!(f, Frame::Disconnect);
    }

    // ── Golden vectors: Event ────────────────────────────────────────────────

    #[test]
    fn parse_frame_event_with_payload() {
        // Real frame shape from server: 42/p2p,["p2p:joined",{"sessionId":"s1","role":"sender"}]
        let raw = r#"42/p2p,["p2p:joined",{"sessionId":"s1","role":"sender"}]"#;
        let f = parse_frame(raw, "p2p");
        assert_eq!(
            f,
            Frame::Event {
                event: "p2p:joined".into(),
                payload: json!({"sessionId": "s1", "role": "sender"}),
            }
        );
    }

    #[test]
    fn parse_frame_event_null_payload() {
        let raw = r#"42/ns,["heartbeat"]"#;
        let f = parse_frame(raw, "ns");
        assert_eq!(
            f,
            Frame::Event {
                event: "heartbeat".into(),
                payload: Value::Null,
            }
        );
    }

    #[test]
    fn parse_frame_event_complex_payload() {
        let raw = r#"42/p2p,["p2p:offer",{"sdp":{"type":"offer","sdp":"v=0\r\n..."}}]"#;
        let f = parse_frame(raw, "p2p");
        match f {
            Frame::Event { event, payload } => {
                assert_eq!(event, "p2p:offer");
                assert_eq!(payload["sdp"]["type"], "offer");
            }
            _ => panic!("expected Event"),
        }
    }

    // ── Golden vectors: Encoding ─────────────────────────────────────────────

    #[test]
    fn encode_namespace_connect_format() {
        assert_eq!(encode_namespace_connect("p2p"), "40/p2p,");
        assert_eq!(encode_namespace_connect("chat"), "40/chat,");
    }

    #[test]
    fn encode_event_format() {
        let encoded = encode_event("p2p", "join", &json!({"sessionId": "abc", "role": "sender"}));
        assert!(encoded.starts_with("42/p2p,"));
        let json_part = encoded.strip_prefix("42/p2p,").unwrap();
        let arr: Vec<Value> = serde_json::from_str(json_part).unwrap();
        assert_eq!(arr[0], "join");
        assert_eq!(arr[1]["sessionId"], "abc");
    }

    #[test]
    fn encode_disconnect_format() {
        assert_eq!(encode_disconnect("p2p"), "41/p2p,");
    }

    // ── Round-trip ───────────────────────────────────────────────────────────

    #[test]
    fn encode_then_parse_event_round_trip() {
        let payload = json!({"key": "value", "num": 42});
        let encoded = encode_event("myns", "my-event", &payload);
        let frame = parse_frame(&encoded, "myns");
        assert_eq!(
            frame,
            Frame::Event {
                event: "my-event".into(),
                payload: json!({"key": "value", "num": 42}),
            }
        );
    }

    // ── Other ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_frame_unknown_returns_other() {
        let f = parse_frame("99garbage", "p2p");
        assert_eq!(f, Frame::Other("99garbage".into()));
    }

    // ── Namespace normalization (leading slash stripped) ──────────────────────

    #[test]
    fn encode_namespace_connect_strips_leading_slash() {
        assert_eq!(encode_namespace_connect("/p2p"), "40/p2p,");
    }

    #[test]
    fn parse_frame_with_leading_slash_ns() {
        let raw = r#"42/p2p,["p2p:joined",{}]"#;
        let f = parse_frame(raw, "/p2p");
        assert_eq!(
            f,
            Frame::Event {
                event: "p2p:joined".into(),
                payload: json!({}),
            }
        );
    }

    #[test]
    fn encode_event_strips_leading_slash() {
        let encoded = encode_event("/p2p", "join", &json!({}));
        assert!(encoded.starts_with("42/p2p,"));
    }

    #[test]
    fn encode_disconnect_strips_leading_slash() {
        assert_eq!(encode_disconnect("/p2p"), "41/p2p,");
    }

    #[test]
    fn parse_namespace_ack_strips_leading_slash() {
        let sid = parse_namespace_ack(r#"40/p2p,{"sid":"ns1"}"#, "/p2p").unwrap();
        assert_eq!(sid, "ns1");
    }
}
