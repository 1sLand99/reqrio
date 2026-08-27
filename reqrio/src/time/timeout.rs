use std::time::{Duration, Instant};
use crate::json::JsonValue;
use crate::error::HlsError;
use crate::TimeError;

#[derive(Clone)]
pub struct Timeout {
    //连接超时
    connect_time: Instant,
    connect_timeout: Duration,
    //读取超时，单次
    read_time: Instant,
    read_timeout: Duration,
    //写出超时，单次
    write_time: Instant,
    write_timeout: Duration,
    //处理超时，总超时
    handle: Duration,
    //连接尝试次数
    connect_times: i32,
    //处理次数
    handle_times: i32,
}

impl Default for Timeout {
    fn default() -> Self {
        Timeout::new_same(3000, 3)
    }
}

impl Timeout {
    pub fn new_same(timeout: u64, handles: i32) -> Timeout {
        Timeout {
            connect_time: Instant::now(),
            connect_timeout: Duration::from_millis(timeout),
            read_time: Instant::now(),
            read_timeout: Duration::from_millis(timeout),
            write_time: Instant::now(),
            write_timeout: Duration::from_millis(timeout),
            handle: Duration::from_millis(timeout),
            connect_times: handles,
            handle_times: handles,
        }
    }

    pub fn longer() -> Timeout {
        Timeout::new_same(u64::MAX, 3)
    }

    pub fn is_peer_closed(&self, status: impl AsRef<str>) -> bool {
        let close_status = vec!["broken pipe", "reset by peer", "关闭", "中止了", "close"];
        let status = status.as_ref().to_lowercase();
        close_status.into_iter().any(|x| status.contains(x))
    }

    pub fn connect(&self) -> Duration {
        self.connect_timeout
    }

    pub fn read(&self) -> Duration {
        self.read_timeout
    }

    pub fn write(&self) -> Duration {
        self.write_timeout
    }

    pub fn handle(&self) -> Duration {
        self.handle
    }

    pub fn connect_times(&self) -> i32 {
        self.connect_times
    }

    pub fn handle_times(&self) -> i32 {
        self.handle_times
    }

    pub fn set_connect(&mut self, millis: u64) {
        self.connect_timeout = Duration::from_millis(millis);
    }

    pub fn set_read(&mut self, millis: u64) {
        self.read_timeout = Duration::from_millis(millis);
    }

    pub fn set_write(&mut self, millis: u64) {
        self.write_timeout = Duration::from_millis(millis);
    }

    pub fn set_handle(&mut self, millis: u64) {
        self.handle = Duration::from_millis(millis);
    }

    pub fn set_connect_times(&mut self, connect_times: i32) {
        self.connect_times = connect_times;
    }

    pub fn set_handle_times(&mut self, handle_times: i32) {
        self.handle_times = handle_times;
        self.connect_times = handle_times;
    }

    pub fn read_timeout(&self) -> Result<(), TimeError> {
        match self.read_time.elapsed() > self.read_timeout {
            true => Err(TimeError::ReadTimeout),
            false => Ok(())
        }
    }

    pub fn write_timeout(&self) -> Result<(), TimeError> {
        match self.write_time.elapsed() > self.write_timeout {
            true => Err(TimeError::ReadTimeout),
            false => Ok(())
        }
    }

    pub fn connect_timeout(&self) -> Result<(), TimeError> {
        match self.connect_time.elapsed() > self.connect_timeout {
            true => Err(TimeError::ConnectTimeout),
            false => Ok(())
        }
    }

    pub fn reset_read(&mut self) {
        self.read_time = Instant::now();
    }

    pub fn reset_write(&mut self) {
        self.write_time = Instant::now();
    }

    pub fn reset_connect(&mut self) {
        self.connect_time = Instant::now();
    }
}

impl TryFrom<JsonValue> for Timeout {
    type Error = HlsError;
    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        Ok(Timeout {
            connect_time: Instant::now(),
            connect_timeout: Duration::from_millis(value["connect"].as_u64()?),
            read_time: Instant::now(),
            read_timeout: Duration::from_millis(value["read"].as_u64()?),
            write_time: Instant::now(),
            write_timeout: Duration::from_millis(value["write"].as_u64()?),
            handle: Duration::from_millis(value["handle"].as_u64()?),
            connect_times: value["connect_times"].as_i32()?,
            handle_times: value["handle_times"].as_i32()?,
        })
    }
}