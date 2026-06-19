# NullSeal CLI

Share secrets, passwords, and files securely from your terminal.

Everything is encrypted on your device before it leaves. The server never sees your data — only you and the person you share with can read it.

## Install

```bash
npm i -g nullseal
```

Or run without installing:

```bash
npx nullseal share "my secret" -p mypassword
```

## Why NullSeal?

- **Zero-knowledge** — Your data is encrypted locally before transmission. The server stores only encrypted blobs it cannot read.
- **Password-protected** — Every share requires a password. Without it, the content is unreadable — even to us.
- **One-time read** — Server shares self-destruct after the first read by default. Use `--no-one-time` to allow multiple reads.
- **Auto-expiry** — Shares expire automatically (default 24 hours, max 7 days). Control with `--ttl`.
- **P2P mode** — Transfer directly between devices using peer-to-peer connections. Data never touches the server.
- **Cross-platform** — Works on macOS (Intel & Apple Silicon) and Linux (x64 & arm64). Share between CLI and web seamlessly.

## Quick Start

### Share a secret

```bash
nullseal share "database password: hunter2" -p mypassword
```

If you omit `-p`, you'll be prompted to enter the password interactively (hidden from shell history):

```bash
nullseal share "database password: hunter2"
# 🔑 Password: ********
```

You'll get a secure link and a QR code. Send the link to the recipient through any channel — the content is safe even if the link is intercepted, because the password is required to decrypt.

### Retrieve a secret

```bash
nullseal get https://nullseal.com/s/abc123xyz -p mypassword
```

### Share a file

```bash
nullseal share ./credentials.pdf -p mypassword -t file
```

### Peer-to-peer transfer

Send directly to another device — no server storage, no size limit:

```bash
# Sender
nullseal share "top secret" -p mypassword -m p2p

# Recipient (use the link from the sender)
nullseal get https://nullseal.com/p2p/abc123xyz -p mypassword
```

P2P transfers happen over an encrypted WebRTC connection. The server only helps the two devices find each other — it never sees the data.

### Local network transfer

Two machines on the same network? Use `-n local` for a fully local transfer — no server needed:

```bash
# Sender
nullseal share "top secret" -m p2p -n local

# Recipient (on same network — auto-discovers sender via mDNS)
nullseal get -n local

# Or connect directly if mDNS doesn't work
nullseal get -n local -a 192.168.1.42:52341
```

The sender binds a local signaling server and broadcasts its address via mDNS. The transfer uses WebRTC — data never leaves your network.

## Usage

```
nullseal share <content> [options]
nullseal get <url-or-id> [options]
```

### Common options

| Flag | Description |
|------|-------------|
| `-p, --password` | Encryption password (prompted interactively if omitted) |

### `share` options

| Flag | Description | Default |
|------|-------------|--------|
| `-m, --mode` | Transfer mode: `u` (server upload) or `p2p` (peer-to-peer) | `u` |
| `-t, --type` | Content type: `txt`, `pwd`, or `file` | `txt` |
| `-T, --ttl` | Expiration: e.g. `1h`, `24h`, `3d`, `7d` (max: 7d) | `24h` |
| `-1, --one-time` | One-time read (negate with `--no-one-time`) | on |
| `-n, --network` | Network mode: `local` = fully local transfer (no server) | off |
| `-a, --address` | Bind address for local transfer (default: auto-detect) | auto |

### `get` options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output directory for received files |
| `-n, --network` | Network mode: `local` = discover sender on LAN |
| `-a, --address` | Direct host:port for local transfer (skip mDNS discovery) |

If `-p` is omitted, you'll be prompted to enter the password interactively. This is recommended to avoid exposing passwords in shell history.

## Security

NullSeal is designed so that **no one except the sender and recipient can read the shared content** — not even the NullSeal service.

- Content is encrypted on your device using a password-derived key with 250,000 rounds of key stretching
- Industry-standard AES-256 encryption with unique random parameters for every share
- The password never leaves your device — only a one-way proof is sent for P2P verification
- Server shares are one-time read and auto-expire
- P2P transfers are end-to-end encrypted — data flows directly between devices
- The CLI is a compiled binary with no runtime dependencies — no supply chain risk from JavaScript packages

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| macOS | Apple Silicon (arm64) |
| macOS | Intel (x64) |
| Linux | x64 |
| Linux | arm64 |

## Links

- Web app: [nullseal.com](https://nullseal.com)

## License

MIT
