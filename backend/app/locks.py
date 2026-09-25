import asyncio


class AsyncReadWriteLock:
    """Allow concurrent scans while giving database maintenance exclusive access."""

    def __init__(self):
        self.condition = asyncio.Condition()
        self.readers = 0
        self.writer = False
        self.waiting_writers = 0

    async def acquire_read(self):
        async with self.condition:
            await self.condition.wait_for(lambda: not self.writer and self.waiting_writers == 0)
            self.readers += 1

    async def release_read(self):
        async with self.condition:
            self.readers -= 1
            if self.readers == 0:
                self.condition.notify_all()

    async def acquire_write(self):
        async with self.condition:
            self.waiting_writers += 1
            try:
                await self.condition.wait_for(lambda: not self.writer and self.readers == 0)
                self.writer = True
            finally:
                self.waiting_writers -= 1

    async def release_write(self):
        async with self.condition:
            self.writer = False
            self.condition.notify_all()


database_access = AsyncReadWriteLock()
