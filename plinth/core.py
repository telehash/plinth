# -*- coding: utf-8 -*-

import os
import time

from tomcrypt import rsa, hash
from gevent.server import DatagramServer

from .log import log
from . import packet


class Switch(DatagramServer):

    def __init__(self, listener=0, key=None, ephemeral=False):
        super(Switch, self).__init__(listener)
        if key is None:
            if not ephemeral:
                raise ValueError("No identity key specified")
            else:
                key = self.new_key()
        if isinstance(key, (str, unicode)):
            self._from_string(key)
        if not self.key.is_private:
            raise ValueError("Invalid private key")
        pub_der = self.key.as_string(format='der')
        self.hash_name = hash.new('sha256', pub_der).hexdigest()

    @staticmethod
    def new_key(size=2048):
        return rsa.Key(size).as_string()

    @property
    def pub_key(self):
        return self.key.public.as_string()

    def _from_string(self, key):
        self.key = rsa.Key(key)

    def start(self, seeds=None):
        log.debug('My public key:\n%s' % self.pub_key)
        log.debug('My hash name: %s' % self.hash_name)
        log.debug('Listening for open packets on port %i' % self.address[1])
        super(Switch, self).start()

    def handle(self, data, address):
        log.debug('Received %i bytes from %s' % (len(data), address[0]))
        try:
            wrapper, payload = packet.decode(data)
        except packet.PacketException, err:
            log.debug('Invalid Packet: %s' % err)
            pass
        log.debug(wrapper)

