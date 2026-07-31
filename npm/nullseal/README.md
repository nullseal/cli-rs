# NullSeal CLI

Share secrets, passwords, files, and folders securely from your terminal.

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
- **One-time read** — Server shares self-destruct after the first read. (From the CLI this is always on; multi-read shares can only be created on the web.)
- **Auto-expiry** — Shares expire automatically (default 24 hours, max 7 days). Control with `-T/--ttl`.
- **P2P mode** — Transfer directly between devices. Data never touches the server, and there is no size limit.
- **Folder sharing** — Send a whole directory as one archive, or sync it file-by-file so repeat runs move only what changed.
- **Cross-platform** — macOS (Intel & Apple Silicon), Linux (x64 & arm64), Windows (x64). Share between CLI and web seamlessly.

## Quick Start

### Share a secret

```bash
nullseal share "database password: hunter2" -p mypassword
```

If you omit `-p`, you'll be prompted to enter the password interactively (hidden from shell history):

```bash
nullseal share "database password: hunter2"
# › Password: ********
```

You'll get a secure link and a QR code. Send the link to the recipient through any channel — the content is safe even if the link is intercepted, because the password is required to decrypt.

### Retrieve a secret

```bash
nullseal get https://nullseal.com/s/abc123xyz -p mypassword
```

### Share a file

```bash
nullseal share ./credentials.pdf -p mypassword --file
```

### Share a folder

A directory needs one of two explicit modes — `--zip` (one archive) or `--sync` (files transferred individually, unchanged ones skipped by hash).

```bash
# Pack the folder into one myfolder.zip and upload it
nullseal share ./myfolder --zip -p mypassword

# Skip files you don't want to send (gitignore syntax, repeatable)
nullseal share ./myfolder --zip -p mypassword --exclude '*.log' --exclude 'node_modules/'

# Sync a folder over the LAN — a repeat run moves only what changed
nullseal share ./myfolder --sync --local -p mypassword
```

`--zip` works in every mode and is **required** for folders in upload mode.
`--sync` needs a direct connection (`--p2p` or `--local`). A `.nullsealignore` file at the folder root is honored too, with full gitignore syntax.

On the receiving side, a zip folder share is extracted automatically:

```bash
# Receive into ./mirror/myfolder — the shared folder name is always appended
nullseal get https://nullseal.com/sync/abc123xyz -p mypassword -o ./mirror

# Keep the archive instead of extracting (zip shares only)
nullseal get https://nullseal.com/p2p/abc123xyz -p mypassword --no-extract

# True mirror: overwrite same-name files AND delete what the sender no longer has
nullseal get https://nullseal.com/sync/abc123xyz -p mypassword -o ./mirror --replace-delete
```

The receiver always works inside `<-o>/<shared folder name>`, creating it if needed — so `-o` is the *parent*, and `--replace-delete` can never touch anything outside that one folder.

Folder-sync links use a `/sync/` prefix and are **CLI-only** — opening one in a browser is a 404 by design.

### Peer-to-peer transfer

Send directly to another device — no server storage, no size limit:

```bash
# Sender
nullseal share "top secret" -p mypassword --p2p

# Recipient (use the link from the sender)
nullseal get https://nullseal.com/p2p/abc123xyz -p mypassword
```

P2P transfers happen over an encrypted WebRTC connection. The server only helps the two devices find each other — it never sees the data.

### Local network transfer

Two machines on the same network? Use `--local` for a fully local transfer — no server needed:

```bash
# Sender
nullseal share "top secret" -p mypassword --local

# Recipient (on the same network — auto-discovers the sender via mDNS)
nullseal get --local -p mypassword

# Or connect directly if mDNS doesn't work
nullseal get --local -a 192.168.1.42:52341 -p mypassword
```

**On a network that blocks UDP**, use `--sync --local`: it carries its data over plain TCP and needs no UDP, STUN or ICE, so it works behind corporate endpoint agents that block UDP. (`--p2p` is WebRTC and still requires UDP.)

### Diagnose a connection

```bash
nullseal check server      # can the CLI reach the backend and create a session?
nullseal check turn        # is STUN/TURN reachable, or is UDP blocked?
```

## Usage

```
nullseal share <content> [options]
nullseal get [<url>] [options]
nullseal manage <ownercode> [options]
nullseal check server|turn
```

### `share` options

| Flag | Description | Default |
|------|-------------|--------|
| `-p, --password` | Encryption password (prompted if omitted) | prompted |
| `--upload` / `--p2p` / `--local` | Transfer mode (`--local` implies `--p2p`) | `--upload` |
| `-m, --mode` | Mode alias: `upload` \| `p2p` \| `local` | `upload` |
| `--text` / `--file` / `--pwd` | Content type | `--text` |
| `--zip` | Pack a directory into one `<folder>.zip` and share that | — |
| `--sync` | Transfer a directory's files directly, no archive (`--p2p` / `--local` only) | — |
| `--exclude <PATTERN>` | Exclude files matching a gitignore-style pattern (repeatable) | — |
| `--exclude-from <FILE>` | Read gitignore-style patterns from a file (repeatable) | — |
| `-t, --type` | Type alias: `txt` \| `file` \| `pwd` \| `zip` \| `sync` | `txt` |
| `-T, --ttl` | Expiration: e.g. `1h`, `24h`, `3d`, `7d` (max 7d), server shares only | `24h` |
| `-1, --one-time` | One-time read — always on for server shares, cannot be disabled from the CLI | on |
| `-a, --address` | Bind IP for local mode (the port is always ephemeral) | auto |

### `get` options

| Flag | Description |
|------|-------------|
| `-p, --password` | Decryption password (prompted if omitted) |
| `-o, --output` | Output directory (for folders, the *parent* of the created folder) |
| `--local` | Discover the sender on the LAN via mDNS |
| `-a, --address` | Direct `host:port` for local transfer (skips mDNS discovery) |
| `--no-extract` | Keep a received folder share as `<folder>.zip` (ignored on a `--sync` transfer) |
| `--replace-delete` | Mirror: overwrite same-name files **and** delete files the sender no longer has |
| `-y, --yes` | Confirm a `--replace-delete` prune whose source list is empty |

### Global options

| Flag | Description |
|------|-------------|
| `--pipe` | Machine-friendly: result only on stdout, no logs, exit code signals failure |
| `--verbose` | Full lifecycle/transport event stream, including ICE diagnostics |

If `-p` is omitted, you'll be prompted to enter the password interactively. This is recommended to avoid exposing passwords in shell history.

## Security

NullSeal is designed so that **no one except the sender and recipient can read the shared content** — not even the NullSeal service.

- Content is encrypted on your device using a password-derived key with 250,000 rounds of key stretching
- Industry-standard AES-256 encryption with unique random parameters for every share
- The password never leaves your device — only a one-way proof is sent for P2P verification
- Server shares are one-time read and auto-expire
- P2P and LAN transfers are end-to-end encrypted — data flows directly between devices
- Folder transfers validate every incoming path and abort rather than write outside the destination folder
- The CLI is a compiled binary with no runtime dependencies — no supply chain risk from JavaScript packages

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| macOS | Apple Silicon (arm64) |
| macOS | Intel (x64) |
| Linux | x64 |
| Linux | arm64 |
| Windows | x64 |

## Links

- Web app: [nullseal.com](https://nullseal.com)

## License

MIT
