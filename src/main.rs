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
#[command(name = "nullseal", about = "Encrypted sharing CLI", version)]
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
        #[arg(short, long, default_value = "u",
              help = "Transfer mode: u=server upload, p2p=peer-to-peer")]
        mode: String,
        #[arg(short = 't', long = "type", default_value = "txt",
              help = "Content type: txt, pwd, file")]
        content_type: String,
        #[arg(short = 'n', long = "network",
              help = "Network mode: local = fully local transfer")]
        network: Option<String>,
        #[arg(short = 'a', long = "address",
              help = "Bind address for local transfer (default: auto-detect)")]
        address: Option<String>,
    },
    #[command(about = "Retrieve and decrypt a share")]
    Get {
        #[arg(help = "Share URL or share ID (omit with -n local to discover)")]
        url: Option<String>,
        #[arg(short, long, help = "Encryption password (prompted if omitted)")]
        password: Option<String>,
        #[arg(short, long, help = "Output directory for received files")]
        output: Option<String>,
        #[arg(short = 'n', long = "network",
              help = "Network mode: local = discover via mDNS")]
        network: Option<String>,
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
        Commands::Share { content, password, mode, content_type, network, address } => {
            let password = password.unwrap_or_else(prompt_password);
            let local = matches!(network.as_deref(), Some("local"));
            if let Some(ref n) = network {
                if n != "local" {
                    eprintln!("\x1b[1;31m✗\x1b[0m Unknown network mode: {n}. Supported: local");
                    std::process::exit(1);
                }
            }
            if local {
                if mode != "p2p" {
                    eprintln!("\x1b[1;31m✗\x1b[0m -n local requires -m p2p");
                    std::process::exit(1);
                }
                commands::share::run_local(content, password, content_type, address, &mut |s| println!("{s}")).await
            } else {
                if address.is_some() {
                    eprintln!("\x1b[1;31m✗\x1b[0m -a/--address requires -n local");
                    std::process::exit(1);
                }
                commands::share::run(content, password, mode, content_type, None, &mut |s| println!("{s}")).await
            }
        }
        Commands::Get { url, password, output, network, address } => {
            let password = password.unwrap_or_else(prompt_password);
            let local = matches!(network.as_deref(), Some("local"));
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
                    eprintln!("\x1b[1;31m✗\x1b[0m -a/--address requires -n local");
                    std::process::exit(1);
                }
                let url = url.unwrap_or_else(|| {
                    eprintln!("\x1b[1;31m✗\x1b[0m Missing <URL>. Provide a share URL or use -n local for local discovery.");
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
