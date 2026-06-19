use clap::{Parser, Subcommand};
use std::io::{self, Write};

mod api;
mod commands;
mod crypto;
mod local;
mod local_signal;
mod socket;
mod webrtc;

#[derive(Parser)]
#[command(name = "nullseal", about = "Encrypted sharing CLI", version,
    after_help = "\x1b[1;4mShare options:\x1b[0m
  -p, --password <PW>    Encryption password (prompted if omitted)
  -m, --mode <MODE>      Transfer mode: u | p2p
  -t, --type <TYPE>      Content type: txt | file
  -n, --network <NET>    Network mode: local
      --file             Share as file
      --text             Share as text (default)
      --p2p              Peer-to-peer transfer via server signaling
      --upload           Short-time upload (default)
      --local            Fully local transfer (implies --p2p)
  -a, --address <ADDR>   Bind address for local transfer

\x1b[1;4mGet options:\x1b[0m
  -p, --password <PW>    Encryption password (prompted if omitted)
  -o, --output <DIR>     Output directory for received files
  -n, --network <NET>    Network mode: local
      --local            Discover sender via mDNS on local network
  -a, --address <ADDR>   Direct host:port for local transfer

\x1b[1;4mExamples:\x1b[0m
  nullseal share \"hello world\" -p mypass
  nullseal share ./doc.pdf -p mypass --file
  nullseal share \"secret\" -p mypass --p2p
  nullseal share \"secret\" -p mypass --local
  nullseal share \"secret\" -p mypass --local -a 192.168.1.5
  nullseal get <URL> -p mypass
  nullseal get -p mypass --local"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Encrypt and share content")]
    Share {
        content: String,
        #[arg(short, long, help = "Encryption password (prompted if omitted)")]
        password: Option<String>,
        // -- value-based flags (legacy) --
        #[arg(short, long, help = "Transfer mode: u=short-time upload, p2p=peer-to-peer")]
        mode: Option<String>,
        #[arg(short = 't', long = "type", help = "Content type: txt, file")]
        content_type: Option<String>,
        #[arg(short = 'n', long = "network", help = "Network mode: local")]
        network: Option<String>,
        // -- boolean flags (new) --
        #[arg(long, help = "Share as file")]
        file: bool,
        #[arg(long, help = "Share as text (default)")]
        text: bool,
        #[arg(long, help = "Peer-to-peer transfer via server signaling")]
        p2p: bool,
        #[arg(long, help = "Short-time upload (default)")]
        upload: bool,
        #[arg(long, help = "Fully local transfer (implies --p2p)")]
        local: bool,
        #[arg(short = 'a', long = "address",
              help = "Bind address for local transfer (default: auto-detect)")]
        address: Option<String>,
    },
    #[command(about = "Retrieve and decrypt a share")]
    Get {
        #[arg(help = "Share URL or share ID (omit with --local to discover)")]
        url: Option<String>,
        #[arg(short, long, help = "Encryption password (prompted if omitted)")]
        password: Option<String>,
        #[arg(short, long, help = "Output directory for received files")]
        output: Option<String>,
        // -- value-based flag (legacy) --
        #[arg(short = 'n', long = "network", help = "Network mode: local")]
        network: Option<String>,
        // -- boolean flag (new) --
        #[arg(long, help = "Discover sender via mDNS on local network")]
        local: bool,
        #[arg(short = 'a', long = "address",
              help = "Direct host:port for local transfer (skip mDNS discovery)")]
        address: Option<String>,
    },
}

fn prompt_password() -> String {
    eprint!("\x1b[1;33m🔑 Password:\x1b[0m ");
    io::stderr().flush().ok();
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap_or(0);
    password.trim().to_owned()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Share { content, password, mode, content_type, network, file, text, p2p, upload, local, address } => {
            let password = password.unwrap_or_else(prompt_password);

            // Merge -n local / --local
            let local = local || matches!(network.as_deref(), Some("local"));
            if let Some(ref n) = network {
                if n != "local" {
                    eprintln!("\x1b[1;31m✗\x1b[0m Unknown network mode: {n}. Supported: local");
                    std::process::exit(1);
                }
            }

            // Merge -t file / --file / --text  (--file or -t file → "file", else "txt")
            let file = file || matches!(content_type.as_deref(), Some("file"));
            let text = text || matches!(content_type.as_deref(), Some("txt"));
            if file && text {
                eprintln!("\x1b[1;31m✗\x1b[0m --file and --text are mutually exclusive");
                std::process::exit(1);
            }
            if let Some(ref t) = content_type {
                if !matches!(t.as_str(), "txt" | "file") {
                    eprintln!("\x1b[1;31m✗\x1b[0m Unknown content type: {t}. Supported: txt, file");
                    std::process::exit(1);
                }
            }
            let resolved_content_type = if file { "file" } else { "txt" };

            // Merge -m p2p / --p2p / --upload
            let p2p = p2p || matches!(mode.as_deref(), Some("p2p"));
            let upload = upload || matches!(mode.as_deref(), Some("u"));
            if p2p && upload {
                eprintln!("\x1b[1;31m✗\x1b[0m --p2p and --upload are mutually exclusive");
                std::process::exit(1);
            }
            if local && upload {
                eprintln!("\x1b[1;31m✗\x1b[0m --local and --upload are mutually exclusive");
                std::process::exit(1);
            }
            if let Some(ref m) = mode {
                if !matches!(m.as_str(), "u" | "p2p") {
                    eprintln!("\x1b[1;31m✗\x1b[0m Unknown mode: {m}. Supported: u, p2p");
                    std::process::exit(1);
                }
            }

            if local {
                commands::share::run_local(content, password, resolved_content_type, address, &mut |s| println!("{s}")).await
            } else {
                if address.is_some() {
                    eprintln!("\x1b[1;31m✗\x1b[0m -a/--address requires --local");
                    std::process::exit(1);
                }
                let resolved_mode = if p2p { "p2p" } else { "u" };
                commands::share::run(content, password, resolved_mode, resolved_content_type, None, &mut |s| println!("{s}")).await
            }
        }
        Commands::Get { url, password, output, network, local, address } => {
            let password = password.unwrap_or_else(prompt_password);

            // Merge -n local / --local
            let local = local || matches!(network.as_deref(), Some("local"));
            if let Some(ref n) = network {
                if n != "local" {
                    eprintln!("\x1b[1;31m✗\x1b[0m Unknown network mode: {n}. Supported: local");
                    std::process::exit(1);
                }
            }

            if local {
                if url.is_some() {
                    eprintln!("\x1b[1;33m⚠\x1b[0m  Ignoring URL argument — using local transfer.");
                }
                commands::get::run_local(password, output, address, &mut |s| println!("{s}")).await
            } else {
                if address.is_some() {
                    eprintln!("\x1b[1;31m✗\x1b[0m -a/--address requires --local");
                    std::process::exit(1);
                }
                let url = url.unwrap_or_else(|| {
                    eprintln!("\x1b[1;31m✗\x1b[0m Missing <URL>. Provide a share URL or use --local for local discovery.");
                    std::process::exit(1);
                });
                commands::get::run(url, password, output, None, &mut |s| println!("{s}")).await
            }
        }
    };

    if let Err(e) = result {
        eprintln!("\x1b[1;31m✗\x1b[0m {e}");
        std::process::exit(1);
    }
}
