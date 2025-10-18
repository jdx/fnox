use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "fnox")]
#[command(about = "A Rust CLI application", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Example command that greets the user
    Greet {
        /// Name of the person to greet
        #[arg(short, long)]
        name: String,
    },
    /// Example command that shows version info
    Version,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Greet { name }) => {
            println!("Hello, {}!", name);
        }
        Some(Commands::Version) => {
            println!("fnox version {}", env!("CARGO_PKG_VERSION"));
        }
        None => {
            println!("fnox - A Rust CLI application");
            println!("Run 'fnox --help' for more information");
        }
    }
}
