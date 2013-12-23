# -*- coding: utf-8 -*-

"""
This should end up as the main user interface to Plinth.
"""

import os
from collections import Counter

from .log import log
from .identity import SwitchID
from .exceptions import *


class Channel(object):
    """Baseline for inter-app communication

    Yes, yes, all this needs some cleanup for fully async-safe behavior.
    """
    def __init__(self, remote, t=None, c=None):
        self.remote = remote
        self.transmit = remote.send
        #hahahahahahahaha, you idiot
        self.local = remote.local
        self.c = c
        self.t = t
        if self.c is None:
            self.c = os.urandom(16).encode('hex')

    def recv(self, data, body):
        log.debug("Channel %s recv:\n%s" % (self.c, data))
        self.handle_unknown(data, body)

    def init(self, data):
        custom = {'_' : data}
        self._send(custom)
        #insert "wait for acceptance of channel" behavior

    def send(self, data):
        custom = {'_' : data}
        self._send(custom)

    def _send(self, data):
        data['c'] = self.c
        self.transmit(data)

    @classmethod
    def incoming(cls, remote, t, c, data, body):
        if t[:1] != '_':
            flavor = ProtocolChannel
        elif 'seq' in data.keys():
            flavor = DurableChannel
        else:
            flavor = Channel
        ch = flavor(remote, t, c)
        ch.recv(data, body)
        return ch

    @classmethod
    def outgoing(cls, remote, t):
        if t[:1] != '_':
            flavor = ProtocolChannel
        else:
            flavor = Channel
        ch = flavor(remote, t)
        return ch

    def handle_unknown(self, data, body):
        if 'err' in data:
            log.debug('Remote error: %s' % data['err'])
            return
        if 'end' in data:
            return
        err = '%s currently unimplemented' % self.t
        resp = {'end': True, 'err': err}
        self._send(resp)

class DurableChannel(Channel):
    """Stub for TCP-like channels"""
    pass


class ProtocolChannel(Channel):
    """Channels managed by the switch, generally not user facing"""
    def __init__(self, remote, t=None, c=None):
        if t not in ('seek', 'peer', 'connect', 'relay'):
            raise ChannelException('Unrecognized channel type: %s' % t)
        #Okay, *this* has to be the last straw, right?
        inbound = False
        if c is not None:
            inbound = True
        super(ProtocolChannel, self).__init__(remote, t, c)
        if inbound:
            self.init(data=None, inbound=True)

    def init(self, data, inbound=False):
        if self.t == 'seek':
            if inbound:
                self.recv = self.handle_seek
            else:
                self.recv = self.handle_see
                seeking = {'type': 'seek', 'seek': data}
                self._send(seeking)
        elif self.t == 'connect' and inbound:
            self.recv = self.handle_connect
        else:
            log.debug('TODO: implement %s' % self.t)
            if inbound:
                self.recv = self.handle_unknown

    def handle_see(self, data, body):
        log.debug('Received see: %s' % data)

    def handle_seek(self, data, body):
        hn = data['seek']
        log.debug('Remote seeking: %s' % hn)
        see_list = self.local.dht.seek(hn)
        resp = {'end': True, 'see': see_list}
        self._send(resp)

    def handle_connect(self, data, body):
        paths = data.get('paths')
        connect_id = SwitchID(key=body)
        remote = self.local.switches.get(connect_id.hash_name)
        if remote is not None:
            remote.id.found_key(body)
        else:
            remote = self.local.add_remote(connect_id)
        if paths is not None:
            for path in paths:
                if path['type'] == 'ipv4':
                    address = (path['ip'], path['port'])
                    remote.new_line(address)
                    self.local.ping(connect_id.hash_name)
                    #no multi-homing yet, so quit now
                    return
