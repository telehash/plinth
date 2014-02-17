# -*- coding: utf-8 -*-

import os

import gevent
from gevent.server import DatagramServer

from .log import log
from .identity import SwitchID
from . import packet
from . import crypto
from .dht import DHT
from .exceptions import *


class Switch(DatagramServer):
    """An application's TeleHash Switch instance.

    Used to communicate securely with other applications over the TeleHash
    mesh network.
    """
    def __init__(self, listener=0, key=None, ephemeral=False, seeds=[]):
        super(Switch, self).__init__(listener)
        if key is None:
            if not ephemeral:
                raise ValueError("No identity key specified")
            else:
                self.id = SwitchID()
        elif isinstance(key, (str, unicode)):
            self.id = SwitchID(key=key)
            if not self.id.is_private:
                raise ValueError("Need private key for local identity")
        else:
            raise ValueError("Private key must be in PEM format.")
        self.dht = DHT(self.id, self.sendto)
        self.seeds = seeds

    def start(self):
        log.debug('My public key:\n%s' % self.id.pub_key)
        log.debug('My hash name: %s' % self.id.hash_name)
        log.debug('Listening for open packets on port %i' % self.address[1])
        super(Switch, self).start()
        for seed in self.seeds:
            seed_id = SwitchID(hash_name=seed['hashname'],
                               key=seed['pubkey'])
            #ideally we modify the seeds.json format to make this cleaner
            paths = []
            try:
                path = {'type': 'ipv4',
                        'ip': seed['ip'],
                        'port': seed['port']}
                paths.append(path)
            except:
                #ipv6 support requires a slightly more extensive rewrite
                continue
            remote = self.dht.register(seed_id, paths)
        self.dht.start()

    def handle(self, data, address):
        log.debug('Received %i bytes from %s' % (len(data), address[0]))
        if len(data) <= 4:
            #Empty / NAT-punching packets can be ignored
            return
        try:
            wrapper, payload = packet.decode(data)
            packet_type = packet.validate_wrapper(wrapper)
            if packet_type == 'open':
                sender_ecc = self.id.decrypt(wrapper['open'])
                sender, line_id, at = crypto.read_open(
                    self.id.hash_name, sender_ecc, wrapper, payload)
                self.dht.handle_open(sender, sender_ecc, line_id, at, address)
            else:
                self.dht.handle_line(wrapper, payload, address)
        except PacketException, err:
            log.debug('Invalid Packet: %s' % err)

    def open_channel(self, hash_name, ctype, initial_data=None):
        ch = gevent.spawn(self.dht.open_channel,
                          hn, cytpe, initial_data)
        ch.get(timeout=5)
        return ch

    def ping(self, hn):
        ch = gevent.spawn(self.dht.open_channel,
                          hn, 'seek', self.id.hash_name)
        ch.get(timeout=5)
        return ch
