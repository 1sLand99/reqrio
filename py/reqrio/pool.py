from reqrio.bindings import DLL, ThreadCallback


class ThreadPool:
    def __init__(self, max_active=10000, timeout=15000, lockable=False):
        """
        :param max_active:最大活跃线程
        :param timeout: 任务超时，毫秒
        """
        self.dll = DLL
        self.pool = self.dll.new_thread_pool(timeout, max_active)
        self._cb = ThreadCallback(self.callback)
        self.funcs = []
        self.args = []
        self.lock_tid = -1
        self.lockable = lockable

    def callback(self, tid):
        func = self.funcs.pop(0)
        args = self.args.pop(0)
        try:
            if self.lockable:
                func(self, tid, *args)
            else:
                func(*args)
        except Exception as e:
            raise e
        finally:
            if self.lock_tid == tid:
                self.dll.thread_pool_release_lock(self.pool)
                self.lock_tid = -1

    def set_max_active(self, count: int):
        self.dll.thread_pool_set_max_active(self.pool, count)

    def set_timeout(self, timeout: int):
        self.dll.thread_pool_set_timeout(self.pool, timeout)

    def run(self, func, *args):
        """
        :param func: 回调函数
        :param args: 函数参数，当lockable为True是，第一、二个参数是ThreadPool和thread_id,后面的参数才是传递的参数
        :return:
        """
        self.funcs.append(func)
        self.args.append(args)
        self.dll.thread_pool_run(self.pool, self._cb)

    def acquire_lock(self, tid):
        """
        线程锁，只会锁子线程，不会卡主线程
        :param tid:
        :return:
        """
        self.dll.thread_pool_acquire_lock(self.pool)
        self.lock_tid = tid

    def release_lock(self, tid):
        if self.lock_tid != tid:
            raise Exception("非本线程的锁，无权释放")
        self.dll.thread_pool_release_lock(self.pool)
        self.lock_tid = -1

    def join(self):
        self.dll.thread_pool_join(self.pool)

    def drop(self):
        self.dll.thread_pool_free(self.pool)

# proxies = []
#
#
# def run_thread(pool: ThreadPool, tid, data):
#     import time
#     pool.acquire_lock(tid)
#     if len(proxies) == 0:
#         time.sleep(5)
#         proxies.append('http://127.0.0.1/')
#     # pool.release_lock(tid)
#
#     time.sleep(15)
#     print(tid, data, proxies)
#
#
# import time
#
# s = time.time()
# pool = ThreadPool(10, 15000, True)
# for i in range(10):
#     pool.run(run_thread, "thread" + str(i))
# for ii in range(5):
#     print(ii)
#     time.sleep(1)
# pool.join()
# pool.drop()
# e = time.time()
# print(e - s)
