# -*- coding: utf-8 -*-

"""
This should end up as the main user interface to Plinth.
"""

import os
from .log import log
#from gevent.queue import Queue


class Channel(object):
    def __init__(self, send_func, c=None, t=None):
        self.transmit = send_func
        self.c = c
        self.t = t
        if self.c is None:
            self.c = os.urandom(16).encode('hex')
            self._outbound = True

    def recv(self, data, body):
        log.debug("Channel %s recv:\n%s" % (self.c, data))

    def send(self, data):
        if self.t == 'seek':
            pkt['seek'] = data
        self._send(pkt)

    def _send(self, data):
        data['c'] = self.c
        self.transmit(data)

@classmethod
def incoming(cls, send_func, c, t, data, body):
    if t[0] != '_':
        flavor = ProtocolChannel
    elif 'seq' in data.keys():
        flavor = DurableChannel
    else:
        flavor = Channel
    ch = flavor(send_func, c, t)
    ch.recv(data, body)
    return ch

class DurableChannel(Channel):
    pass

class ProtocolChannel(Channel):
    def __init__(self, *args, **kwargs):
        if t not in ('seek', 'peer', 'connect'):
            raise Exception('Unknown protocol channel type: %s' % t)
        super(ProtocolChannel, self).__init__(self, *args, **kwargs)
        pass
