from aiotuya import MessageParser
import json
data = b'\x00\x00U\xaa\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00E\x00\x00\x00\x00{"devId":"05200058dc4f22850214","dps":{"1":false,"11":0}}-\x86<\xe6\x00\x00\xaaU\x00\x00U\xaa\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00E\x00\x00\x00\x00{"devId":"05200058dc4f22850214","dps":{"1":false,"11":0}}-\x86<\xe6\x00\x00\xaaU'
data = b'\x00\x00U\xaa\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x8b\x00\x00\x00\x003.12961eb3457dc736ebYpIvNcnoG2km9pjouoHCOD0fTngnMOZopyRxB7TqUcRzoy9ImVJFhZw0NtqfMM2jaIN0GyQVBtQuRsNXIbmIKC+GV/'
for (error,result,command) in MessageParser().extract_payload(data, '453c43bc759a1b35'.encode()):
    if(error == False):
        print('Resolve string=%s (command:%i)', result, command)
