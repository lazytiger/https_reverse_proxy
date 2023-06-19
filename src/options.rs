use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Options {

    /// file path for save log, default to stdout
    #[arg(short = 'L', long, default_value = "")]
    pub log_file:String,

    /// log level, 0 to 4 represents TRACE, DEBUG, INFO, WARN, ERROR, others mean OFF
    #[arg(short = 'E', long, default_value = "2")]
    pub log_level:u8,

    /// file path for root CA certificate pem
    #[arg(short, long)]
    pub ca_crt_path:String,

    /// file path for root CA key pem
    #[arg(short = 'k', long)]
    pub ca_key_path:String,

    /// address for listening, like 0.0.0.0:443
    #[arg(short, long)]
    pub listen_address:String,
}