"""
Simple platform to control **SOME** Tuya switch devices.

For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/switch.tuya/
"""
import voluptuous as vol
from homeassistant.components.switch import SwitchDevice, PLATFORM_SCHEMA
from homeassistant.const import (CONF_NAME, CONF_HOST, CONF_ID, CONF_SWITCHES, CONF_FRIENDLY_NAME)
import homeassistant.helpers.config_validation as cv
from time import time
import logging
from aiotuya import OutletDevice, TuyaDevice, resolveId
import asyncio

REQUIREMENTS = ['https://github.com/thecrazymonkey/python-tuya-async/archive/master.zip#aiotuya==0.7.1']

CONF_DEVICE_ID = 'device_id'
CONF_LOCAL_KEY = 'local_key'

DEFAULT_ID = '1'

SWITCH_SCHEMA = vol.Schema({
    vol.Optional(CONF_ID, default=DEFAULT_ID): cv.string,
    vol.Optional(CONF_FRIENDLY_NAME): cv.string,
})

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_NAME): cv.string,
    vol.Optional(CONF_HOST,default=''): cv.string,
    vol.Required(CONF_DEVICE_ID): cv.string,
    vol.Required(CONF_LOCAL_KEY): cv.string,
    vol.Optional(CONF_ID, default=DEFAULT_ID): cv.string,
    vol.Optional(CONF_SWITCHES, default={}):
        vol.Schema({cv.slug: SWITCH_SCHEMA}),
})

_LOGGER = logging.getLogger(__name__)

async def async_setup_platform(hass, config, async_add_devices, discovery_info=None):
    """Set up of the Tuya switch."""
    devices = config.get(CONF_SWITCHES)

    _LOGGER.debug("Starting IP Discovery")
#    if config.get(CONF_HOST) == None:
#        parser = aiotuya.MessageParser()
#        ipResolver = TuyaIPDiscovery(config.get(CONF_DEVICE_ID), parser)
#        coro = hass.loop.create_datagram_endpoint(
#            lambda: ipResolver, local_addr=('255.255.255.255', 6666))
#        ipResolver.task = hass.async_add_job(coro)
    devices = config.get(CONF_SWITCHES)
    switches = []
    switchstatus = dict()
    if config.get(CONF_HOST) == None:
        config.set(CONF_HOST, await hass.async_add_executor_job(resolveId(config.get(CONF_DEVICE_ID))))

    outlet_device = OutletDevice(
            hass,
            config.get(CONF_DEVICE_ID),
            config.get(CONF_LOCAL_KEY),
            config.get(CONF_HOST)
        )

    for object_id, device_config in devices.items():
        tuyadevice = TuyaPlug(
                outlet_device,
                device_config.get(CONF_FRIENDLY_NAME, object_id),
                device_config.get(CONF_ID),
            )
        switches.append(tuyadevice)
        _LOGGER.debug("async_setup_platform adding {0}".format(config.get(CONF_ID)))
        switchstatus[config.get(CONF_ID)] = { 'status' : None, 'parent' : tuyadevice }

    name = config.get(CONF_NAME)
    if name:
        tuyadevice = TuyaPlug(
                    outlet_device,
                    name,
                    config.get(CONF_ID)
                )
        switches.append(tuyadevice)
        _LOGGER.debug("async_setup_platform adding {0}".format(config.get(CONF_ID)))
        switchstatus[config.get(CONF_ID)] = { 'status' : None, 'parent' : tuyadevice }

    outlet_device.switches = switchstatus
    outlet_device.tuyadevice = outlet_device
    coro = hass.loop.create_connection(lambda: outlet_device,
                             config.get(CONF_HOST), 8888)
    async_add_devices(switches, update_before_add=True)
    hass.async_add_job(coro)
    return True

class TuyaIPDiscovery(asyncio.DatagramProtocol):
    def __init__(self, id, parser):
        self._id = id
        self._parser = parser
        self._address = None
        self.task = None

    def connection_made(self, transport):
        self.transport = transport
        _LOGGER.debug("Starting Discovery UDP server")

    def datagram_received(self, data, addr):
        (error,result) =self._parser.extract_payload(data)

        if(error == False):
            _LOGGER.debug('Resolve string=%s', result)
            thisId = result['gwId']
            # check if already registered, if not add to the list and create a handler instance
            if thisId == self._id:
                _LOGGER.debug('Discovered=%s on IP=%s', thisId,result['ip'])
                self.transport.close()

    def connection_lost(self, exc):
        _LOGGER.debug("Disconnected %s",exc)
        self.task.cancel()

    def getAddress(self):
        return self._address


class TuyaPlug(SwitchDevice):
    """Representation of a Tuya switch."""

    def __init__(self, device, name, switchid):
        """Initialize the Tuya switch."""
        self._device = device
        self._name = name
        self._state = False
        self._switchid = switchid

    @property
    def name(self):
        """Get name of Tuya switch."""
        return self._name

    @property
    def is_on(self):
        """Check if Tuya switch is on."""
        return self._state

    async def async_turn_on(self, **kwargs):
        """Turn Tuya switch on."""
        self._device.set_status(True, self._switchid)

    async def async_turn_off(self, **kwargs):
        """Turn Tuya switch off."""
        self._device.set_status(False, self._switchid)

    async def async_update(self):
        """Get state of Tuya switch."""
        # should come automatically
        # status = self._device.status()
        self._state = self._device.switches[self._switchid]
