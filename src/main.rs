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
  -T, --ttl <TTL>        Expiration: e.g. 1h, 24h, 3d, 7d (default: 24h, max: 7d)
  -1, --one-time         One-time read (default; negate with --no-one-time)
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

\x1b[1;4mManage options:\x1b[0m
  -c, --command <CMD>    Action: replace | destroy
      --replace          Replace share content (shorthand for -c replace)
      --destroy          Destroy share permanently (shorthand for -c destroy)
  -p, --password <PW>    Encryption password (required for replace)
  -t, --type <TYPE>      Content type: txt, pwd, file (must match original)
      --file             Replace with file content

\x1b[1;4mExamples:\x1b[0m
  nullseal share \"hello world\" -p mypass
  nullseal share \"secret\" -p mypass -T 1h
  nullseal share \"secret\" -p mypass --ttl 3d --no-one-time
  nullseal share ./doc.pdf -p mypass --file
  nullseal share \"secret\" -p mypass --p2p
  nullseal share \"secret\" -p mypass --local
  nullseal share \"secret\" -p mypass --local -a 192.168.1.5
  nullseal get <URL> -p mypass
  nullseal get -p mypass --local
  nullseal manage \"id@secret\" --replace \"new content\" -p mypass
  nullseal manage \"id@secret\" --destroy"
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
        // -- value-based flags --
        #[arg(short, long, help = "Transfer mode: u=short-time upload, p2p=peer-to-peer")]
        mode: Option<String>,
        #[arg(short = 't', long = "type", help = "Content type: txt, file")]
        content_type: Option<String>,
        #[arg(short = 'n', long = "network", help = "Network mode: local")]
        network: Option<String>,
        // -- boolean flags --
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
        #[arg(short = 'T', long = "ttl",
              help = "Expiration: e.g. 1h, 24h, 3d, 7d (default: 24h, max: 7d)")]
        ttl: Option<String>,
        #[arg(short = '1', long = "one-time", default_value_t = true,
              help = "One-time read (default: true; negate with --no-one-time)")]
        one_time: bool,
    },
    #[command(about = "Retrieve and decrypt a share")]
    Get {
        #[arg(help = "Share URL or share ID (omit with --local to discover)")]
        url: Option<String>,
        #[arg(short, long, help = "Encryption password (prompted if omitted)")]
        password: Option<String>,
        #[arg(short, long, help = "Output directory for received files")]
        output: Option<String>,
        // -- value-based flag --
        #[arg(short = 'n', long = "network", help = "Network mode: local")]
        network: Option<String>,
        // -- boolean flag (new) --
        #[arg(long, help = "Discover sender via mDNS on local network")]
        local: bool,
        #[arg(short = 'a', long = "address",
              help = "Direct host:port for local transfer (skip mDNS discovery)")]
        address: Option<String>,
    },
    #[command(about = "Replace or destroy a share using an owner code")]
    Manage {
        #[arg(help = "Owner code (format: shareId@secret)")]
        owner_code: String,
        #[arg(short, long, help = "Encryption password (required for replace)")]
        password: Option<String>,
        #[arg(help = "New content (for replace)")]
        content: Option<String>,
        // -- action flags --
        #[arg(short = 'c', long = "command", help = "Action: replace or destroy")]
        action: Option<String>,
        #[arg(long, help = "Replace share content (shorthand for -c replace)")]
        replace: bool,
        #[arg(long, help = "Destroy share permanently (shorthand for -c destroy)")]
        destroy: bool,
        // -- content type --
        #[arg(short = 't', long = "type", help = "Content type: txt, pwd, file")]
        content_type: Option<String>,
        #[arg(long, help = "Replace with file content")]
        file: bool,
    },
}

fn prompt_password() -> String {
    eprint!("\x1b[1;33m🔑 Password:\x1b[0m ");
    io::stderr().flush().ok();
    rpassword::read_password().unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Share { content, password, mode, content_type, network, file, text, p2p, upload, local, address, ttl, one_time } => {
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
                commands::share::run(content, password, resolved_mode, resolved_content_type, None, ttl, one_time, &mut |s| println!("{s}")).await
            }
        }
        Commands::Manage { owner_code, password, content, action, replace, destroy, content_type, file } => {
            // Resolve action from -c flag or boolean shorthands
            let resolved_action = if destroy {
                "destroy".to_string()
            } else if replace {
                "replace".to_string()
            } else if let Some(a) = action {
                a
            } else {
                eprintln!("\x1b[1;31m✗\x1b[0m Missing action. Use --replace or --destroy (or -c replace / -c destroy).");
                std::process::exit(1);
            };

            if resolved_action != "replace" && resolved_action != "destroy" {
                eprintln!("\x1b[1;31m✗\x1b[0m Unknown action: {resolved_action}. Supported: replace, destroy");
                std::process::exit(1);
            }

            let password = if resolved_action == "replace" {
                Some(password.unwrap_or_else(prompt_password))
            } else {
                password
            };

            // Resolve content type
            let content_type_flag = if file {
                "file".to_string()
            } else {
                content_type.unwrap_or_else(|| "txt".to_string())
            };

            commands::manage::run(owner_code, resolved_action, content, password, content_type_flag, None, &mut |s| println!("{s}")).await
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
