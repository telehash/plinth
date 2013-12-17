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

    def recv(self, data, body):
        log.debug("Channel %s recv:\n%s" % (self.c, data))

    def send(self, data):
        """Janky logic goes here for a little bit"""
        pkt = {
            'type': self.t
        }
        if self.t == 'seek':
            pkt['seek'] = data
        self._send(pkt)

    def _send(self, data):
        data['c'] = self.c
        self.transmit(data)

"""
class DurableChannel(Channel):
    def __init__(self):
        super(DurableChannel, self).__init__(self)
        self.inq = Queue()
        self.outq = Queue()
"""
