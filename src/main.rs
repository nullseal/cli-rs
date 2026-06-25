use clap::{Parser, Subcommand};
use std::io::{self, Write};

mod api;
mod commands;
mod crypto;
mod local;
mod local_server;
mod p2p;
mod retry;
mod webrtc;

#[derive(Parser)]
#[command(name = "nullseal", about = "Encrypted sharing CLI", version,
    after_help = "\x1b[1;4mGlobal options:\x1b[0m
      --pipe             Machine-friendly: result to stdout, no logs (conflicts with --verbose)
      --verbose          Verbose: print the full lifecycle/transport event stream
      --stdin            Read content from stdin instead of argument

\x1b[1;4mShare options:\x1b[0m
  -p, --password <PW>    Encryption password (prompted if omitted)
      --upload           Short-time upload (default)
      --p2p              Peer-to-peer transfer via server signaling
      --local            Fully local transfer (implies --p2p)
  -m, --mode <MODE>      Mode alias: upload | p2p | local
      --text             Share as text (default)
      --file             Share as file
      --pwd              Share as a password-type secret
  -t, --type <TYPE>      Type alias: txt | file | pwd
  -T, --ttl <TTL>        Expiration: e.g. 1h, 24h, 3d, 7d (default: 24h, max: 7d)
  -1, --one-time         One-time read (default; negate with --no-one-time)
  -a, --address <ADDR>   Bind address for local transfer

\x1b[1;4mGet options:\x1b[0m
  -p, --password <PW>    Encryption password (prompted if omitted)
  -o, --output <DIR>     Output directory for received files
      --local            Discover sender via mDNS on local network
  -a, --address <ADDR>   Direct host:port for local transfer (skips mDNS)

\x1b[1;4mManage options:\x1b[0m
  -c, --command <CMD>    Action: replace | destroy
      --replace          Replace share content (shorthand for -c replace)
      --destroy          Destroy share permanently (shorthand for -c destroy)
  -p, --password <PW>    Encryption password (required for replace)
      --text             Replace with text content (default)
      --file             Replace with file content
      --pwd              Replace with a password-type secret
  -t, --type <TYPE>      Type alias: txt | file | pwd (must match original)

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
    /// Machine-friendly output: write only the result to stdout, no logs, exit code only
    #[arg(long, global = true)]
    pipe: bool,

    /// Verbose output: print the full lifecycle/transport event stream (conflicts with --pipe)
    #[arg(long, global = true, conflicts_with = "pipe")]
    verbose: bool,

    /// Read content from stdin instead of argument
    #[arg(long, global = true)]
    stdin: bool,

    /// Force relay-only mode (TURN relay, no direct/srflx candidates)
    #[arg(long, global = true, hide = true)]
    relay_only: bool,

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
        #[arg(short, long, help = "Transfer mode (alias for the booleans): upload | p2p | local")]
        mode: Option<String>,
        #[arg(short = 't', long = "type", help = "Content type (alias for the booleans): txt | file | pwd")]
        content_type: Option<String>,
        // -- boolean flags --
        #[arg(long, help = "Share as file")]
        file: bool,
        #[arg(long, help = "Share as text (default)")]
        text: bool,
        #[arg(long, help = "Share as a password-type secret")]
        pwd: bool,
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
        // -- boolean flag --
        #[arg(long, help = "Discover sender via mDNS on local network (or use -a for a direct address)")]
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
        // -- content type (must match the original share) --
        #[arg(short = 't', long = "type", help = "Content type (alias for the booleans): txt | file | pwd")]
        content_type: Option<String>,
        #[arg(long, help = "Replace with text content (default)")]
        text: bool,
        #[arg(long, help = "Replace with file content")]
        file: bool,
        #[arg(long, help = "Replace with a password-type secret")]
        pwd: bool,
    },
}

fn prompt_password() -> String {
    eprint!("\x1b[1;33m🔑 Password:\x1b[0m ");
    io::stderr().flush().ok();
    rpassword::read_password().unwrap_or_default()
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()
        .expect("failed to build tokio runtime");
    rt.block_on(async_main());
}

async fn async_main() {
    let cli = Cli::parse();
    let pipe_mode = cli.pipe;
    let relay_only = cli.relay_only;

    // Establish the global verbosity for the leveled logger. `--pipe` wins (it
    // already conflicts with `--verbose` at the clap layer, so they can't both be
    // set, but this ordering is explicit).
    let verbosity = if cli.pipe {
        commands::log::Verbosity::Pipe
    } else if cli.verbose {
        commands::log::Verbosity::Verbose
    } else {
        commands::log::Verbosity::Normal
    };
    commands::log::init(verbosity);

    // Read from stdin if --stdin flag is set
    let stdin_content = if cli.stdin {
        use std::io::Read;
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).ok();
        Some(buf)
    } else {
        None
    };

    let result = match cli.command {
        Commands::Share { content, password, mode, content_type, file, text, pwd, p2p, upload, local, address, ttl, one_time } => {
            let content = stdin_content.unwrap_or(content);
            let password = if pipe_mode {
                password.unwrap_or_default()
            } else {
                password.unwrap_or_else(prompt_password)
            };

            // Validate the -t/--type alias value up front.
            if let Some(ref t) = content_type {
                if !matches!(t.as_str(), "txt" | "file" | "pwd") {
                    commands::log::error(&format!("Unknown content type: {t}. Supported: txt, file, pwd"));
                    std::process::exit(1);
                }
            }
            // Merge content type: --file/--text/--pwd booleans + -t/--type alias.
            let file = file || matches!(content_type.as_deref(), Some("file"));
            let text = text || matches!(content_type.as_deref(), Some("txt"));
            let pwd = pwd || matches!(content_type.as_deref(), Some("pwd"));
            if (file as u8 + text as u8 + pwd as u8) > 1 {
                commands::log::error("--file, --text and --pwd are mutually exclusive");
                std::process::exit(1);
            }
            let resolved_content_type = if file { "file" } else if pwd { "password" } else { "txt" };

            // Validate the -m/--mode alias value (upload | p2p | local; `u` = upload back-compat).
            if let Some(ref m) = mode {
                if !matches!(m.as_str(), "upload" | "u" | "p2p" | "local") {
                    commands::log::error(&format!("Unknown mode: {m}. Supported: upload, p2p, local"));
                    std::process::exit(1);
                }
            }
            // Merge transfer mode: --upload/--p2p/--local booleans + -m/--mode alias.
            // NB: don't fold `local` into `p2p` — dispatch routes `--local` to run_local
            // regardless, and `resolved_mode` is only read on the non-local branch. Folding
            // it made `--local --upload` trip the `p2p && upload` check (wrong message).
            let local = local || matches!(mode.as_deref(), Some("local"));
            let p2p = p2p || matches!(mode.as_deref(), Some("p2p"));
            let upload = upload || matches!(mode.as_deref(), Some("upload" | "u"));
            if p2p && upload {
                commands::log::error("--p2p and --upload are mutually exclusive");
                std::process::exit(1);
            }
            if local && upload {
                commands::log::error("--local and --upload are mutually exclusive");
                std::process::exit(1);
            }

            if local {
                commands::share::run_local(content, password, resolved_content_type, address, &mut |s| commands::log::result(s)).await
            } else {
                if address.is_some() {
                    commands::log::error("-a/--address requires --local");
                    std::process::exit(1);
                }
                let resolved_mode = if p2p { "p2p" } else { "u" };
                commands::share::run(content, password, resolved_mode, resolved_content_type, None, ttl, one_time, relay_only, &mut |s| commands::log::result(s)).await
            }
        }
        Commands::Manage { owner_code, password, content, action, replace, destroy, content_type, text, file, pwd } => {
            // Resolve action from -c flag or boolean shorthands
            let resolved_action = if destroy {
                "destroy".to_string()
            } else if replace {
                "replace".to_string()
            } else if let Some(a) = action {
                a
            } else {
                commands::log::error("Missing action. Use --replace or --destroy (or -c replace / -c destroy).");
                std::process::exit(1);
            };

            if resolved_action != "replace" && resolved_action != "destroy" {
                commands::log::error(&format!("Unknown action: {resolved_action}. Supported: replace, destroy"));
                std::process::exit(1);
            }

            let password = if resolved_action == "replace" {
                Some(password.unwrap_or_else(prompt_password))
            } else {
                password
            };

            // Validate the -t/--type alias and resolve content type from the
            // --text/--file/--pwd booleans (must match the original share).
            if let Some(ref t) = content_type {
                if !matches!(t.as_str(), "txt" | "file" | "pwd") {
                    commands::log::error(&format!("Unknown content type: {t}. Supported: txt, file, pwd"));
                    std::process::exit(1);
                }
            }
            let file = file || matches!(content_type.as_deref(), Some("file"));
            let text = text || matches!(content_type.as_deref(), Some("txt"));
            let pwd = pwd || matches!(content_type.as_deref(), Some("pwd"));
            if (file as u8 + text as u8 + pwd as u8) > 1 {
                commands::log::error("--file, --text and --pwd are mutually exclusive");
                std::process::exit(1);
            }
            let content_type_flag = if file {
                "file".to_string()
            } else if pwd {
                "pwd".to_string()
            } else {
                "txt".to_string()
            };

            commands::manage::run(owner_code, resolved_action, content, password, content_type_flag, None, &mut |s| commands::log::result(s)).await
        }
        Commands::Get { url, password, output, local, address } => {
            let password = if pipe_mode {
                password.unwrap_or_default()
            } else {
                password.unwrap_or_else(prompt_password)
            };

            if local {
                if url.is_some() {
                    commands::display::warn("Ignoring URL argument — using local transfer.");
                }
                commands::get::run_local(password, output, address, &mut |s| commands::log::result(s)).await
            } else {
                if address.is_some() {
                    commands::log::error("-a/--address requires --local");
                    std::process::exit(1);
                }
                let url = url.unwrap_or_else(|| {
                    commands::log::error("Missing <URL>. Provide a share URL or use --local for local discovery.");
                    std::process::exit(1);
                });
                commands::get::run(url, password, output, None, relay_only, &mut |s| commands::log::result(s)).await
            }
        }
    };

    if let Err(e) = result {
        // `error` is pipe-aware (suppressed in Pipe → exit code only).
        commands::log::error(&format!("{e}"));
        std::process::exit(1);
    }
}
