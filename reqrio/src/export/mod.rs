use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::ptr::null_mut;
use std::sync::{Arc, LazyLock, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;
use reqrio_json::JsonValue;
use crate::error::HlsResult;
use crate::json;

mod req;
mod wss;

fn unique_id() -> i32 {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let res = nanos << 8;
    (res as i32).abs()
}

fn time_sec() -> u64 {
    let sec = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    sec
}

fn time_millis() -> u128 {
    let millis = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    millis
}

struct Inner {
    locked: bool,
    locked_id: i32,
    last_lock: u64,
}

pub struct DataLock {
    inner: Arc<Mutex<Inner>>,
}

impl DataLock {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                locked: false,
                locked_id: 0,
                last_lock: 0,
            })),
        }
    }

    pub fn lock(&self) -> i32 {
        loop {
            let mut inner = self.inner.lock().unwrap();

            if inner.locked && time_sec() - inner.last_lock < 15 {
                drop(inner);
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }

            inner.locked = true;
            inner.locked_id = unique_id();
            inner.last_lock = time_sec();

            return inner.locked_id;
        }
    }
}


// #[repr(C)]
// pub struct DataLock {
//     locked: Arc<Mutex<bool>>,
//     locked_id: i32,
//     inner: Arc<Mutex<JsonValue>>,
//     last_lock: u64,
// }
//
// impl DataLock {
//     pub fn lock(&self) -> HlsResult<i32> {
//         loop {
//             // 锁住 Arc 内部的 Mutex
//             let mut guard = self.locked.lock()?;
//
//             if *guard && time_sec() - self.last_lock < 15 {
//                 drop(guard);
//                 std::thread::sleep(Duration::from_millis(100));
//                 continue;
//             }
//
//             // 成功加锁
//             *guard = true;
//
//             // 这里需要修改 self.locked_id 和 self.last_lock
//             // 因为 self 是不可变引用，我们必须把这两个字段放到 Mutex 内部，或者用 Atomic
//             // 假设你把 last_lock 和 locked_id 也放进 Mutex 内部：
//             let locked_id = unique_id();
//             // self.locked_id.store(locked_id, Ordering::Relaxed); // 如果是 AtomicI32
//             // self.last_lock.store(time_sec(), Ordering::Relaxed); // 如果是 AtomicI64 或 AtomicU64
//
//             return Ok(locked_id);
//         }
//     }
//
//     pub fn release_lock(&mut self, lid: i32) -> HlsResult<()> {
//         if self.locked_id != lid { return Ok(()); }
//         let mut locked = self.locked.lock()?;
//         *locked = false;
//         self.locked_id = 0;
//         Ok(())
//     }
// }
//
// #[unsafe(no_mangle)]
// pub extern "C" fn new_data_lock(data: *const c_char) -> *mut DataLock {
//     || -> HlsResult<*mut DataLock> {
//         let data = unsafe { CStr::from_ptr(data) }.to_bytes();
//         Ok(Box::into_raw(Box::new(DataLock {
//             locked: Arc::new(Mutex::new(false)),
//             locked_id: 0,
//             inner: Arc::new(Mutex::new(json::from_bytes(data)?)),
//             last_lock: 0,
//         })))
//     }().unwrap_or_else(|_| null_mut())
// }
//
// #[unsafe(no_mangle)]
// pub extern "C" fn data_acquire_lock(data: *mut DataLock) -> i32 {
//     || -> HlsResult<i32> {
//         let data = unsafe { data.as_mut() }.ok_or("null ptr")?;
//         data.lock()
//     }().unwrap_or_else(|_| -1)
// }
//
// #[unsafe(no_mangle)]
// pub extern "C" fn data_release_lock(data: *mut DataLock, lid: i32) -> i32 {
//     || -> HlsResult<i32> {
//         let data = unsafe { data.as_mut() }.ok_or("null ptr")?;
//         data.release_lock(lid)?;
//         Ok(0)
//     }().unwrap_or_else(|_| -1)
// }


// #[unsafe(no_mangle)]
// pub extern "C" fn data_lock_free(data: *mut DataLock) {
//     unsafe { drop(Box::from_raw(data)) }
// }

#[repr(C)]
pub struct ThreadPool {
    threads: Vec<(u128, JoinHandle<()>)>,
    timeout: u128,
    max_active_count: usize,
    lock: Arc<Mutex<bool>>,
}

pub type ThreadCallback = extern "C" fn(i32);

impl ThreadPool {
    fn wait_thread(&mut self) {
        while self.threads.len() >= self.max_active_count {
            let mut deletes = vec![];
            for (index, (t, thread)) in self.threads.iter().enumerate() {
                if time_millis() - t > self.timeout || thread.is_finished() { deletes.push(index); }
            }
            deletes.reverse();
            for index in deletes {
                self.threads.remove(index);
            }
            sleep(Duration::from_millis(100))
        }
    }


    pub fn run(&mut self, callback: ThreadCallback) {
        self.wait_thread();
        self.threads.push((time_millis(), spawn(move || callback(unique_id()))));
    }

    pub fn join(&mut self) {
        while !self.threads.is_empty() {
            let _ = self.threads.remove(0).1.join();
        }
    }

    pub fn acquire_lock(&self) -> HlsResult<()> {
        loop {
            let mut locked = self.lock.lock().unwrap();
            if !*locked {
                *locked = true;
                drop(locked);
                return Ok(());
            }
            drop(locked);
            sleep(Duration::from_millis(100));
        }
    }

    pub fn release_lock(&self) -> HlsResult<()> {
        let mut locked = self.lock.lock().unwrap();
        *locked = false;
        drop(locked);
        Ok(())
    }

    pub fn set_timeout(&mut self, timeout: u128) {
        self.timeout = timeout;
    }

    pub fn set_max_active_count(&mut self, max_active_count: usize) {
        self.max_active_count = max_active_count;
    }
}


#[unsafe(no_mangle)]
pub extern "C" fn new_thread_pool(timeout: i32, max_active_count: i32) -> *mut ThreadPool {
    || -> HlsResult<*mut ThreadPool> {
        Ok(Box::into_raw(Box::new(ThreadPool {
            threads: vec![],
            timeout: timeout as u128,
            max_active_count: max_active_count as usize,
            lock: Arc::new(Mutex::new(false)),
        })))
    }().unwrap_or_else(|_| null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pool_run(pool: *mut ThreadPool, callback: ThreadCallback) -> i32 {
    || -> HlsResult<i32> {
        let pool = unsafe { pool.as_mut() }.ok_or("null ptr")?;
        pool.run(callback);
        Ok(0)
    }().unwrap_or_else(|_| -1)
}


#[unsafe(no_mangle)]
pub extern "C" fn thread_pool_join(pool: *mut ThreadPool) -> i32 {
    || -> HlsResult<i32> {
        let pool = unsafe { pool.as_mut() }.ok_or("null ptr")?;
        pool.join();
        Ok(0)
    }().unwrap_or_else(|_| -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pool_free(data: *mut ThreadPool) {
    unsafe { drop(Box::from_raw(data)) }
}


#[unsafe(no_mangle)]
pub extern "C" fn thread_pool_acquire_lock(pool: *mut ThreadPool) -> i32 {
    || -> HlsResult<i32> {
        let pool = unsafe { pool.as_mut() }.ok_or("null ptr")?;
        pool.acquire_lock()?;
        Ok(0)
    }().unwrap_or_else(|_| -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pool_release_lock(pool: *mut ThreadPool) -> i32 {
    || -> HlsResult<i32> {
        let pool = unsafe { pool.as_mut() }.ok_or("null ptr")?;
        pool.release_lock()?;
        Ok(0)
    }().unwrap_or_else(|_| -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pool_set_timeout(pool: *mut ThreadPool, timeout: i32) -> i32 {
    || -> HlsResult<i32> {
        let pool = unsafe { pool.as_mut() }.ok_or("null ptr")?;
        pool.set_timeout(timeout as u128);
        Ok(0)
    }().unwrap_or_else(|_| -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pool_set_max_active(pool: *mut ThreadPool, max_active: i32) -> i32 {
    || -> HlsResult<i32> {
        let pool = unsafe { pool.as_mut() }.ok_or("null ptr")?;
        pool.set_max_active_count(max_active as usize);
        Ok(0)
    }().unwrap_or_else(|_| -1)
}






