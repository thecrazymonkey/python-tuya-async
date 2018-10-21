import asyncio
import pytuya
import logging
from pytuya import OutletDevice

log = logging.getLogger(__name__)
logging.basicConfig()  # TODO include function name/line numbers in log
log.setLevel(level=logging.DEBUG)  # Debug hack!

loop = asyncio.get_event_loop()
print("Starting TCP client")
# One protocol instance will be created to serve all client requests
switch = OutletDevice('05200058dc4f22850214','e04346aada4d6c51','192.168.1.220')
(reader,writer)=loop.run_until_complete(switch.connect(loop))
res=loop.run_until_complete(switch.status())
print('Res is ', res)
res=loop.run_until_complete(switch.turn_on())
print('Res is ', res)
res=loop.run_until_complete(switch.turn_off())
print('Res is ', res)
#log.debug('Status %s', loop.run_until_complete(switch.status()))
#res = loop.run_until_complete(switch.turn_off())
#try:
#    loop.run_forever()
#except KeyboardInterrupt:
#    pass
loop.close()
