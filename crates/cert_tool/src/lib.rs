//! Certificate management tool library

use clap::Parser;

/// Command line arguments for the certificate tool
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Directory containing certificates
    #[arg(short, long)]
    pub input_dir: String,
}

/// Parse command line arguments
pub fn parse_args() -> Args {
    Args::parse()
}
