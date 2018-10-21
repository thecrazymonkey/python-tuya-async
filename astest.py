import asyncio
import pytuya
import logging

log = logging.getLogger(__name__)
class IPResolver:
    def __init__(self, id):
        self._payload = None
        self._id = id
        self._address = None
        self._parser = pytuya.MessageParser()

    def connection_made(self, transport):
        self.transport = transport
        log.debug("Starting UDP server")

    def datagram_received(self, data, addr):
        (error,result) =self._parser.extract_payload(data)

        if(error == False):
            log.debug('Resolve string=%s', result)
            thisId = result['gwId']
            if (self._id == thisId):
                # Add IP
                self._address = result['ip']
                # Change product key if neccessary
                # self.productKey = result['productKey'].encode('latin1')

                # Change protocol version if necessary
                # self.version = result['version']
                self.transport.close()
    def connection_lost(self, exc):
        log.debug("Disconnected %s",exc)

    def getAddress(self):
        return self._address

async def test():
    await asyncio.sleep(1.0)
    print('sleep done')

loop = asyncio.get_event_loop()
print("Starting UDP server")
# One protocol instance will be created to serve all client requests
ipResolver = IPResolver("05200058dc4f22850214")
listen = loop.create_datagram_endpoint(
        lambda: ipResolver, local_addr=('255.255.255.255', 6666))

loop.run_until_complete(test())
transport, protocol = loop.run_until_complete(listen)
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

print('Received %r' % (ipResolver.getAddress()))
transport.close()
loop.close()
