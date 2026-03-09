mod cmd;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod public_identity;

#[derive(Parser)]
#[command(
    name    = "obsidianq",
    version,
    about   = "Post-quantum capable file encryption utility",
    long_about = None,
)]
struct Cli {
    /// Verbose logging (set RUST_LOG for fine-grained control)
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Key management and public identity export
    Key(cmd::key::KeyArgs),

    /// Contact import workflows
    Contacts(cmd::contacts::ContactsArgs),

    /// Generate a fresh ML-KEM-768 keypair
    #[command(hide = true)]
    Keygen(cmd::keygen::KeygenArgs),

    /// Encrypt a file
    Encrypt(cmd::encrypt::EncryptArgs),

    /// Decrypt a file
    Decrypt(cmd::decrypt::DecryptArgs),

    /// Exchange encrypted packets (.obsqx) using PQC key exchange
    Exchange(cmd::exchange::ExchangeArgs),

    /// Inspect an .obsq file header without decrypting
    Inspect(cmd::inspect::InspectArgs),

    /// Run built-in throughput benchmarks
    Benchmark(cmd::benchmark::BenchmarkArgs),

    /// Mount a container as a read-only virtual drive (requires WinFSP)
    Mount(cmd::mount::MountArgs),

    /// Unmount a previously mounted virtual drive
    Unmount(cmd::unmount::UnmountArgs),

    /// Native vault (.vault) — create / add / extract / ls / mount / unmount
    Vault(cmd::vault::VaultArgs),

    /// Secure Connect helper primitives (GUI integration)
    SecureConnect(cmd::secure_connect::SecureConnectArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match cli.command {
        Commands::Key(args) => cmd::key::run(args),
        Commands::Contacts(args) => cmd::contacts::run(args),
        Commands::Keygen(args) => cmd::keygen::run(args),
        Commands::Encrypt(args) => cmd::encrypt::run(args),
        Commands::Decrypt(args) => cmd::decrypt::run(args),
        Commands::Exchange(args) => cmd::exchange::run(args),
        Commands::Inspect(args) => cmd::inspect::run(args),
        Commands::Benchmark(args) => cmd::benchmark::run(args),
        Commands::Mount(args) => cmd::mount::run(args),
        Commands::Unmount(args) => cmd::unmount::run(args),
        Commands::Vault(args) => cmd::vault::run(args),
        Commands::SecureConnect(args) => cmd::secure_connect::run(args),
    }
}
