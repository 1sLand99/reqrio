use std::time::Duration;
use crate::json::JsonValue;
use crate::error::HlsError;

pub struct Timeout {
    //连接超时
    connect: Duration,
    //读取超时，单次
    read: Duration,
    //写出超时，单次
    write: Duration,
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
            connect: Duration::from_millis(timeout),
            read: Duration::from_millis(timeout),
            write: Duration::from_millis(timeout),
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
        self.connect
    }

    pub fn read(&self) -> Duration {
        self.read
    }

    pub fn write(&self) -> Duration {
        self.write
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
        self.connect = Duration::from_millis(millis);
    }

    pub fn set_read(&mut self, millis: u64) {
        self.read = Duration::from_millis(millis);
    }

    pub fn set_write(&mut self, millis: u64) {
        self.write = Duration::from_millis(millis);
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
}

impl TryFrom<JsonValue> for Timeout {
    type Error = HlsError;
    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        Ok(Timeout {
            connect: Duration::from_secs(value["connect"].as_u64()?),
            read: Duration::from_secs(value["read"].as_u64()?),
            write: Duration::from_secs(value["write"].as_u64()?),
            handle: Duration::from_secs(value["handle"].as_u64()?),
            connect_times: value["connect_times"].as_i32()?,
            handle_times: value["handle_times"].as_i32()?,
        })
    }
}