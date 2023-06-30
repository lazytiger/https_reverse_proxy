use std::fs::File;
use std::io::Write;
use std::mem::MaybeUninit;

use clap::Parser;
use tokio::runtime::Runtime;

use crate::cert_resolver::gen_root_ca;
use crate::options::{Command, Options};
use crate::types::Result;

mod acceptor;
mod cache;
mod cert_resolver;
mod file_stream;
mod logger;
mod options;
mod tls_stream;
mod types;
mod utils;

static mut OPTIONS: MaybeUninit<Options> = MaybeUninit::uninit();

pub fn options<'a>() -> &'a Options {
    unsafe { OPTIONS.assume_init_ref() }
}

fn main() {
    let ops = Options::parse();
    unsafe {
        OPTIONS.write(ops);
    }

    logger::setup_logger(options().log_file.as_str(), options().log_level).unwrap();
    match options().command {
        Command::Run(_) => {
            if let Err(err) = run() {
                log::error!("run failed:{:?}", err);
            }
        }
        Command::Generate(_) => {
            if let Err(err) = gen() {
                log::error!("generate failed:{:?}", err);
            }
        }
    }
}

fn gen() -> Result<()> {
    let (ca_crt, ca_key) = gen_root_ca()?;

    let mut file = File::create(&options().ca_crt_path)?;
    file.write_all(ca_crt.as_bytes())?;

    let mut file = File::create(&options().ca_key_path)?;
    file.write_all(ca_key.as_bytes())?;

    Ok(())
}

fn run() -> Result<()> {
    let runtime = Runtime::new()?;
    let _ = runtime.block_on(cache::run())?;
    Ok(())
}
