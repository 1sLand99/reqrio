use std::fs::OpenOptions;
use std::io::Write;
use crate::{Level, Log, Metadata, Record, Time};

pub struct Logger {
    pub module: &'static [(&'static str, Level)],
    pub debug_file: Option<&'static str>,
    pub info_file: Option<&'static str>,
    pub warn_file: Option<&'static str>,
    pub error_file: Option<&'static str>,
    pub out_file: Option<&'static str>,
}

impl Logger {
    pub fn color(&self, level: Level) -> &str {
        match level {
            Level::Error => "\x1b[01;31m",
            Level::Warn => "\x1b[01;33m",
            Level::Info => "\x1b[01;32m",
            Level::Debug => "\x1b[01;35m",
            Level::Trace => "\x1b[01;36m"
        }
    }
}
impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        for (m, l) in self.module {
            if metadata.target().starts_with(m) {
                return &metadata.level() <= l;
            }
        }
        metadata.level() <= reqtls::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) { return; }
        let module = record.module_path().map(|x| {
            let mut items = x.split("::").collect::<Vec<_>>();
            while items.len() > 2 {
                items.remove(1);
            }
            items.join("-")
        }).unwrap_or("??".to_string());
        let t=Time::now_utc8().unwrap();
        println!("{}{} [{:5}] {:20}:{:4}\x1b[0m - {}",
                 self.color(record.metadata().level()),
                 t.as_rfc3339(),
                 record.level(),
                 module,
                 record.line().unwrap_or(0),
                 record.args(),
        );
        let f = match record.level() {
            Level::Error => self.error_file.or(self.out_file),
            Level::Warn => self.warn_file.or(self.out_file),
            Level::Info => self.info_file.or(self.out_file),
            Level::Debug => self.debug_file.or(self.out_file),
            Level::Trace => self.out_file,
        };
        if let Some(f) = f {
            let mut f = OpenOptions::new().create(true).append(true).open(f).unwrap();
            f.write_all(format!(
                "{} [{:5}] {:20}:{:4} - {}\n",
                t.as_rfc3339(),
                record.level(),
                module,
                record.line().unwrap_or(0),
                record.args()).as_bytes()).unwrap();
        }
    }

    fn flush(&self) {}
}