use crate::{Level, Log, Metadata, Record, Time};

pub struct Logger;

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

    pub fn get_file(&self, file: Option<&str>) -> String {
        let file = file.unwrap_or("???").replace("\\", "/");
        if !file.starts_with("/") && file.find(":") != Some(1) {
            let mut items = file.split("/");
            let module = items.next().unwrap_or("??");
            let file = items.last().unwrap_or("??");
            format!("{}-{}", module, file)
        } else { file }
    }
}
impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Error
    }

    fn log(&self, record: &Record) {
        println!("{}{} [{:5}] {:20}:{:4}\x1b[0m - {}",
                 self.color(record.metadata().level()),
                 Time::now().unwrap().rfc3339(),
                 record.level(),
                 self.get_file(record.file()),
                 record.line().unwrap_or(0),
                 record.args(),
        );
    }

    fn flush(&self) {}
}