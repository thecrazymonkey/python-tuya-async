import asyncio

# Borrowed from http://curio.readthedocs.org/en/latest/tutorial.html.
class Test(object):
    def __init__(self):
        pass
#    @asyncio.coroutine
    async def countdown(self,number, n):
        while n > 0:
            print('T-minus', n, '({})'.format(number))
            tt = await asyncio.sleep(1)
            n -= 1
testik = Test()
loop = asyncio.get_event_loop()
tasks = [
    asyncio.ensure_future(testik.countdown("A", 2)),
    asyncio.ensure_future(testik.countdown("B", 3))]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
