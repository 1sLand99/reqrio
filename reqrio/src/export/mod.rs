use crate::error::HlsResult;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;

mod req;
mod wss;

fn unique_id() -> i32 {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let res = nanos << 8;
    (res as i32).abs()
}

// fn time_sec() -> u64 {
//     let sec = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
//     sec
// }

fn time_millis() -> u128 {
    let millis = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    millis
}

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






