#!/usr/bin/env python3
from queue import Empty
from multiprocessing import Queue, Event, Process, cpu_count
from time import sleep


class WorkerContext:
    def __init__(self):
        self._work_queue = Queue()
        self._result_queue = Queue()
        self._message_queue = Queue()

    @property
    def work_queue(self):
        return self._work_queue

    @property
    def result_queue(self):
        return self._result_queue

    @property
    def message_queue(self):
        return self._message_queue


class WorkerPool:
    def __init__(self):
        self._task_running = False
        self._task_completed = Event()
        self._context = WorkerContext()
        self.results = None

    def handle_message_queue(self):
        while True:
            try:
                print(self._context.message_queue.get(timeout=1))
            except Empty:
                if self._task_completed.is_set():
                    self._task_completed.clear()
                    break

    def get_results(self):
        compiled_results = []

        while True:
            try:
                result = self._context.result_queue.get(timeout=1)
            except Empty:
                break

            compiled_results += result

        return compiled_results

    def add_task(self, task):
        self._context.work_queue.put(task)

    def add_tasks(self, tasks):
        for task in tasks:
            self.add_task(task)

    def work_tasks(self, target, worker_count=None, args=None, kwargs=None):
        if self._task_running:
            raise RuntimeError('You cannot run two tasks on one pool at the same time!')

        self._task_running = True

        if not worker_count:
            worker_count = cpu_count()

        workers = []

        # We prepare some default arguments, if none are set.
        args = args or []

        kwargs = {
            'context': self._context,
            **(kwargs or {})
        }

        for _ in range(worker_count):
            workers.append(Process(target=target, args=args, kwargs=kwargs))

        message_worker = Process(target=self.handle_message_queue)
        message_worker.start()

        # We start up our workers, now that the message worker is ready.
        for worker in workers:
            worker.start()

        # We make sure all the workers close before returning.
        while self._context.result_queue.qsize() < worker_count:
            sleep(1)

        self.results = self.get_results()

        for worker in workers:
            worker.terminate()

        self._task_completed.set()
        message_worker.join()

        self._task_running = False
