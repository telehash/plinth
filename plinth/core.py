# -*- coding: utf-8 -*-

import os
import time

from gevent.server import DatagramServer

from .log import log
from . import packet
from .dht import DHT
from .identity import SwitchID


class Switch(DatagramServer):
    """An application's TeleHash Switch instance.

    Used to communicate securely with other applications over the TeleHash
    mesh network.
    """
    def __init__(self, listener=0, key=None, ephemeral=False, seeds=None):
        super(Switch, self).__init__(listener)
        if key is None:
            if not ephemeral:
                raise ValueError("No identity key specified")
            else:
                self.id = SwitchID()
        if isinstance(key, (str, unicode)):
            self.id = SwitchID(key=key)
            if not self.id.is_private:
                raise ValueError("Need private key for local identity")
        #TODO: Need to handle key object edge cases.
        self.dht = DHT(self.id, seeds)

    def start(self):
        log.debug('My public key:\n%s' % self.id.pub_key)
        log.debug('My hash name: %s' % self.id.hash_name)
        log.debug('Listening for open packets on port %i' % self.address[1])
        super(Switch, self).start()
        self.dht.start()

    def handle(self, data, address):
        log.debug('Received %i bytes from %s' % (len(data), address[0]))
        try:
            wrapper, payload = packet.decode(data)
        except packet.PacketException, err:
            log.debug('Invalid Packet: %s' % err)
            pass
        log.debug(wrapper)

