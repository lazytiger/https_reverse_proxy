use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Options {
    /// file path for save log, default to stdout
    #[arg(short = 'L', long, default_value = "")]
    pub log_file: String,

    /// log level, 0 to 4 represents TRACE, DEBUG, INFO, WARN, ERROR, others mean OFF
    #[arg(short = 'E', long, default_value = "2")]
    pub log_level: u8,

    /// file path for root CA certificate pem
    #[arg(short, long)]
    pub ca_crt_path: String,

    /// file path for root CA key pem
    #[arg(short = 'k', long)]
    pub ca_key_path: String,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Parser)]
pub enum Command {
    #[clap(version, name = "run", about = "run in https reverse proxy mode")]
    Run(RunArgs),
    #[clap(version, name = "gen", about = "generate a root ca")]
    Generate(GenerateArgs),
}

#[derive(Parser)]
pub struct RunArgs {
    /// socket address for listening, like 0.0.0.0:443
    #[arg(short, long)]
    pub listen_address: String,

    /// directory for storing generated certificate
    #[arg(short, long)]
    pub certificate_store: String,

    /// directory for storing cached data
    #[arg(short = 'C', long)]
    pub cache_store: String,

    /// a list of content-type which will be cached
    #[arg(short = 't', long)]
    pub content_types: Vec<String>,

    /// buffer size in KB for file transfer
    #[arg(short, long, default_value = "16")]
    pub file_buffer_size: usize,

    /// buffer size in KB for network transfer
    #[arg(short, long, default_value = "4")]
    pub net_buffer_size: usize,
}

#[derive(Parser)]
pub struct GenerateArgs {}

impl Options {
    pub fn as_run(&self) -> &RunArgs {
        match &self.command {
            Command::Run(args) => args,
            _ => unreachable!(),
        }
    }

    #[allow(dead_code)]
    pub fn as_generate(&self) -> &GenerateArgs {
        match &self.command {
            Command::Generate(args) => args,
            _ => unreachable!(),
        }
    }
}
