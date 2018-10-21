# Python module to interface with Shenzhen Xenon ESP8266MOD WiFi smart devices
# E.g. https://wikidevi.com/wiki/Xenon_SM-PW701U
#   SKYROKU SM-PW701U Wi-Fi Plug Smart Plug
#   Wuudi SM-S0301-US - WIFI Smart Power Socket Multi Plug with 4 AC Outlets and 4 USB Charging Works with Alexa
#
# This would not exist without the protocol reverse engineering from
# https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
#
# Python code Forked from clach04/python-tuya
# Modified for Hass to use asyncio
# Tested with Python 3.5.3 only


import base64
from hashlib import md5
import json
import logging
import socket
import sys
import time
import colorsys
import struct
import asyncio

try:
    #raise ImportError
    import Crypto
    from Crypto.Cipher import AES  # PyCrypto
except ImportError:
    Crypto = AES = None
    import pyaes  # https://github.com/ricmoo/pyaes


log = logging.getLogger(__name__)

log.debug('Python %s on %s', sys.version, sys.platform)
if Crypto is None:
    log.debug('Using pyaes version %r', pyaes.VERSION)
    log.debug('Using pyaes from %r', pyaes.__file__)
else:
    log.debug('Using PyCrypto %r', Crypto.version_info)
    log.debug('Using PyCrypto from %r', Crypto.__file__)

SET = 'set'
RESOLVE_PORT=6666

PROTOCOL_VERSION_BYTES = b'3.1'

IS_PY2 = sys.version_info[0] == 2

# This is intended to match requests.json payload at https://github.com/codetheweb/tuyapi
payload_dict = {
  "device": {
    "status": {
      "hexByte": "0a",
      "command": {"gwId": "", "devId": ""}
    },
    "set": {
      "hexByte": "07",
      "command": {"devId": "", "uid": "", "t": ""}
    },
    "prefix": "000055aa"+"00000000"+"000000",    # Next byte is command byte ("hexByte") some zero padding, then length of remaining payload, i.e. command + suffix (unclear if multiple bytes used for length, zero padding implies could be more than one byte)
    "suffix": "000000000000aa55"
  }
}

class AESCipher(object):
    def __init__(self, key):
        #self.bs = 32  # 32 work fines for ON, does not work for OFF. Padding different compared to js version https://github.com/codetheweb/tuyapi/
        self.bs = 16
        self.key = key
    def encrypt(self, raw):
        if Crypto:
            raw = self._pad(raw)
            cipher = AES.new(self.key, mode=AES.MODE_ECB)
            crypted_text = cipher.encrypt(raw)
        else:
            _ = self._pad(raw)
            cipher = pyaes.blockfeeder.Encrypter(pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
            crypted_text = cipher.feed(raw)
            crypted_text += cipher.feed()  # flush final block
        #print('crypted_text %r' % crypted_text)
        #print('crypted_text (%d) %r' % (len(crypted_text), crypted_text))
        crypted_text_b64 = base64.b64encode(crypted_text)
        #print('crypted_text_b64 (%d) %r' % (len(crypted_text_b64), crypted_text_b64))
        return crypted_text_b64
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        #print('enc (%d) %r' % (len(enc), enc))
        #enc = self._unpad(enc)
        #enc = self._pad(enc)
        #print('upadenc (%d) %r' % (len(enc), enc))
        if Crypto:
            cipher = AES.new(self.key, AES.MODE_ECB)
            raw = cipher.decrypt(enc)
            #print('raw (%d) %r' % (len(raw), raw))
            return self._unpad(raw).decode('utf-8')
            #return self._unpad(cipher.decrypt(enc)).decode('utf-8')
        else:
            cipher = pyaes.blockfeeder.Decrypter(pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
            plain_text = cipher.feed(enc)
            plain_text += cipher.feed()  # flush final block
            return plain_text
    def _pad(self, s):
        padnum = self.bs - len(s) % self.bs
        return s + padnum * chr(padnum).encode()
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

class MessageParser(object):
    def __init__(self, dev_type = None):
        self.dev_type = dev_type

    def generate_payload(self, command, options = None):
        """
        Generate the payload to send.

        Args:
            command(str): The type of command.
                This is one of the entries from payload_dict
            data(dict, optional): The data to be send.
                This is what will be passed via the 'dps' entry
            options(dict, optional): parameters used for message composition for a specific entity
             local_key, id, uid
        """
        json_data = payload_dict[self.dev_type][command]['command']

        if 'gwId' in json_data:
            json_data['gwId'] = options["id"]
        if 'devId' in json_data:
            json_data['devId'] = options["id"]
        if 'uid' in json_data:
            json_data['uid'] = options["uid"]
        if 't' in json_data:
            json_data['t'] = str(int(time.time()))

        if options is not None and "data" in options:
            json_data['dps'] = options["data"]

        # Create byte buffer from hex data
        json_payload = json.dumps(json_data)
        #print(json_payload)
        json_payload = json_payload.replace(' ', '')  # if spaces are not removed device does not respond!
        json_payload = json_payload.encode('utf-8')
        log.debug('json_payload=%r', json_payload)

        if command == SET:
            # need to encrypt
            #print('json_payload %r' % json_payload)
            self.cipher = AESCipher(options["local_key"])  # expect to connect and then disconnect to set new
            json_payload = self.cipher.encrypt(json_payload)
            #print('crypted json_payload %r' % json_payload)
            preMd5String = b'data=' + json_payload + b'||lpv=' + PROTOCOL_VERSION_BYTES + b'||' + options["local_key"]
            #print('preMd5String %r' % preMd5String)
            m = md5()
            m.update(preMd5String)
            #print(repr(m.digest()))
            hexdigest = m.hexdigest()
            #print(hexdigest)
            #print(hexdigest[8:][:16])
            json_payload = PROTOCOL_VERSION_BYTES + hexdigest[8:][:16].encode('latin1') + json_payload
            #print('data_to_send')
            #print(json_payload)
            #print('crypted json_payload (%d) %r' % (len(json_payload), json_payload))
            #print('json_payload  %r' % repr(json_payload))
            #print('json_payload len %r' % len(json_payload))
            #print(bin2hex(json_payload))
            self.cipher = None  # expect to connect and then disconnect to set new


        postfix_payload = hex2bin(bin2hex(json_payload) + payload_dict[self.dev_type]['suffix'])
        #print('postfix_payload %r' % postfix_payload)
        #print('postfix_payload %r' % len(postfix_payload))
        #print('postfix_payload %x' % len(postfix_payload))
        #print('postfix_payload %r' % hex(len(postfix_payload)))
        assert len(postfix_payload) <= 0xff
        postfix_payload_hex_len = '%x' % len(postfix_payload)  # TODO this assumes a single byte 0-255 (0x00-0xff)
        buffer = hex2bin( payload_dict[self.dev_type]['prefix'] +
                          payload_dict[self.dev_type][command]['hexByte'] +
                          '000000' +
                          postfix_payload_hex_len ) + postfix_payload
        #print('command', command)
        #print('prefix')
        #print(payload_dict[self.dev_type][command]['prefix'])
        #print(repr(buffer))
        #print(bin2hex(buffer, pretty=True))
        #print(bin2hex(buffer, pretty=False))
        #print('full buffer(%d) %r' % (len(buffer), buffer))
        return buffer

    def extract_payload(self,data,local_key=None):
        """ Return the dps status in json format in a tuple (bool,json)
            if(bool): an error occur and the json is not relevant
            else: no error detected and the status is in json format

        Args:
            data: The data received by send_receive function
            local_key: Optional - needed for encrypted messages (sometimes Tuya returns them - a bug probably)
        """
        # nothing received
        if (data == None):
            return (True, data,None)

        # Check for length
        if (len(data) < 16):
            log.debug('Packet too small. Length: %d', len(data))
            return (True, data, None)

        if (data.startswith(b'\x00\x00U\xaa') == False):
            raise ValueError('Magic prefix mismatch : %s',data)

        if (data.endswith(b'\x00\x00\xaaU') == False):
            raise ValueError('Magic suffix mismatch : %s',data)

        command = struct.unpack_from('>I',data,8)[0]
        log.debug('command = %i', command)

        payloadSize = struct.unpack_from('>I',data,12)[0]
        log.debug('payloadSize = %i', payloadSize)

        # Check for payload
        if (len(data) - 8 < payloadSize):
            log.debug('Packet missing payload. %i;%i', len(data), payloadSize)
            return (True, data, None)

        # extract payload without prefix, suffix, CRC
        payload = data[20:20+payloadSize-12]
        log.debug('payload = %s', payload)
        # encrypted payload comes with version first
        if (payload.startswith(PROTOCOL_VERSION_BYTES) == True):
            # cut prefix and digest and decrypt
            payload = payload[19:]
            self.cipher = AESCipher(local_key)
            payload = self.cipher.decrypt(payload)
            log.debug('Decrypted payload = %s', payload)
            self.cipher = None
        else:
            payload = payload.decode().lstrip('\x00')

        try:
            payload = json.loads(payload)
        except json.decoder.JSONDecodeError as e:
            # warning if this is not an ack
            if command != 7:
                log.warn('JSON payload empty. %s;%s', payload, e)
        log.debug('JSON payload = %s', payload)

        return (False, payload, command)


def bin2hex(x, pretty=False):
    if pretty:
        space = ' '
    else:
        space = ''
    if IS_PY2:
        result = ''.join('%02X%s' % (ord(y), space) for y in x)
    else:
        result = ''.join('%02X%s' % (y, space) for y in x)
    return result


def hex2bin(x):
    if IS_PY2:
        return x.decode('hex')
    else:
        return bytes.fromhex(x)


class TuyaDevice(asyncio.Protocol):
    def __init__(self, loop, parent, dev_id, local_key, address=None, dev_type=None):
        """
        Represents a Tuya device.

        Args:
            dev_id (str): The device id.
            address (str): The network address.
            local_key (str, optional): The encryption key. Defaults to None.
            dev_type (str, optional): The device type.
                It will be used as key for lookups in payload_dict.
                Defaults to None.

        Attributes:
            port (int): The port to connect to.
        """
        self.id = dev_id
        self.address = address
        self.local_key = local_key.encode('latin1')
        self.dev_type = dev_type
        self.version = PROTOCOL_VERSION_BYTES
        self.port = 6668  # default - do not expect caller to pass in
        self.uid = ''
        self.parser = MessageParser(dev_type)
        self.options = { 'id' : dev_id, 'uid' : self.uid, 'local_key' : self.local_key }
        # store all switches state in a structure
        self.tuyadevice = None
        self.loop = loop
        self.transport = None
        self.parent = parent

    def connection_made(self, transport):
        log.debug('TuyaDevice:connection_made()')
        if self.transport is None:
            self.transport = transport
            # call on first connect to get the right status
            self.parent.on_init()
            self.parent.register_job(self.status())
        else:
            self.transport = transport
        log.debug('TuyaDevice:connection_made() - end')

    def data_received(self, data):
        log.debug('TuyaDevice:data_received(): %s',data)
        (error,result,command) = self.parser.extract_payload(data, self.local_key)
        # if ok and not just command ack (7)
        if error == False and command != 7:
            # check what we got - pass structure on, else nothing to do
            if type(result) is dict:
                self.parent.data_parsed(result)
        log.debug('TuyaDevice:data_received() - end')


    def connection_lost(self, exc):
        log.error('TuyaDevice:connection_lost(): %s', exc)
        # need reconnect if died due exception
        if exc != '':
            self.parent.on_connection_lost(exc)
            coro = self.loop.create_connection(lambda: self.tuyadevice,
                             self.address, 6668)
            self.parent.register_job(coro)
            log.debug('New connection attempted - added job')

    def send_data(self, data):
        log.debug('TuyaDevice:send_data() %s', data)
        if self.transport is not None:
            self.transport.write(data)
        else:
            log.debug('TuyaDevice:send_data() - no transport')

    def __repr__(self):
        return '%r' % ((self.id, self.address),)  # FIXME can do better than this

    async def status(self):
        log.debug('TuyaDevice:status()')
        self.options.pop('data', None)
        payload = self.parser.generate_payload('status', self.options)
        self.send_data(payload)

    async def set_status(self, on, switch=1):
        """
        Set status of the device to 'on' or 'off'.
        Args:
            on(bool):  True for 'on', False for 'off'.
            switch(int): The switch to set
        """
        log.debug('TuyaDevice:set_status() entry')
        if isinstance(switch, int):
            switch = str(switch)  # index and payload is a string
        self.options["data"] = {switch:on}
        payload = self.parser.generate_payload(SET, self.options)
        self.send_data(payload)

    async def turn_on(self, switch=1):
        """Turn the device on"""
        log.debug('TuyaDevice:turn_on() entry')
        return await self.set_status(True, switch)

    async def turn_off(self, switch=1):
        """Turn the device off"""
        log.debug('turn_off() entry')
        return await self.set_status(False, switch)

class OutletDevice(TuyaDevice):
    def __init__(self, loop, parent, dev_id, local_key, address=None):
        dev_type = 'device'
        super(OutletDevice, self).__init__(loop, parent, dev_id, local_key, address, dev_type)


def resolveId(thisId) -> str:
    """Find Tuya device IP given device ID"""
    thisIP = None
    log.debug('resolveId()')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        log.debug('Binding to local port %d', RESOLVE_PORT)
        sock.bind(('<broadcast>', RESOLVE_PORT))
    except:
        pass
    # get it to run for 5 seconds to allow all switches to report
    t_end = time.time() + 5
    while time.time() < t_end:
        try:
            data, addr = sock.recvfrom(2048)
            log.debug('Received=%s:%s', data, addr)
            (error,result,command) = MessageParser().extract_payload(data)
        except socket.timeout:
            log.error('No data received during resolveId call')
            error = True

        if(error == False):
            log.debug('Resolve string=%s (command:%i)', result, command)
            if (result['gwId'] == thisId):
                # Add IP
                thisIP = result['ip']
                break
    sock.close()
    log.debug('Resolved IP=%s', thisIP)
    return thisIP
