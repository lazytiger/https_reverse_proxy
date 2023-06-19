use std::path::Path;

pub fn setup_logger(logfile: &str, level: u8) -> crate::types::Result<()> {
    let path = Path::new(logfile);
    if path.exists() {
        let mut suffix = 1;
        loop {
            let new_file = logfile.to_string() + "." + suffix.to_string().as_str();
            let path = Path::new(new_file.as_str());
            if !path.exists() {
                std::fs::rename(logfile, new_file.as_str())?;
                break;
            } else {
                suffix += 1;
            }
        }
    }
    let level = match level {
        0x00 => log::LevelFilter::Trace,
        0x01 => log::LevelFilter::Debug,
        0x02 => log::LevelFilter::Info,
        0x03 => log::LevelFilter::Warn,
        0x04 => log::LevelFilter::Error,
        _ => log::LevelFilter::Off,
    };
    let mut builder = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}:{}][{}]{}",
                chrono::Local::now().format("[%Y-%m-%d %H:%M:%S%.6f]"),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.level(),
                message
            ))
        })
        .level(level);
    if !logfile.is_empty() {
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let path = std::path::Path::new(logfile);
                builder = builder.chain(fern::log_reopen(path, Some(libc::SIGUSR2)).unwrap());
            } else {
                builder = builder.chain(fern::log_file(logfile).unwrap());
            }
        }
    } else {
        builder = builder.chain(std::io::stdout());
    }
    builder.apply()?;
    Ok(())
}
