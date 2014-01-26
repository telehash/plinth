# -*- coding: utf-8 -*-

"""
This should end up as the main user interface to Plinth.
"""

import os
import gevent
from gevent.queue import Queue

from .log import log
from .identity import SwitchID
from .exceptions import *


class Channel(gevent.Greenlet):
    """Baseline for inter-app communication"""

    def __init__(self, remote, t, c=None):
        super(Channel, self).__init__()
        self.remote = remote
        self.transmit = remote.send
        self.c = c
        self.t = t
        self.inq = Queue()
        self.wait_for_roundtrip = False
        if self.c is None:
            self.wait_for_roundtrip = True
            self.c = os.urandom(16).encode('hex')

    def _run(self):
        self.running = True
        if self.wait_for_roundtrip:
            data, body = self.inq.get()
            self._recv_first(data, body)
            #explicit, but not required
            self.wait_for_roundtrip = False
            gevent.sleep(0)
        while self.running:
            data, body = self.inq.get()
            self._recv(data, body)

    def _recv_first(self, data, body):
        log.debug("Channel %s recv:\n%s" % (self.c, data))
        self.handle_unknown(data, body)

    def _recv(self, data, body):
        log.debug("Channel %s recv:\n%s" % (self.c, data))
        self.handle_unknown(data, body)

    def send(self, data, body=''):
        data['c'] = self.c
        self.transmit(data, body)

    def handle_unknown(self, data, body):
        if 'err' in data:
            log.debug('Remote error: %s' % data['err'])
            return
        if 'end' in data:
            return
        err = '%s currently unimplemented' % self.t
        resp = {'end': True, 'err': err}
        #log.debug('To %s: %s' % (remote.id.hash_name, err))
        self.send(resp)


class DurableChannel(Channel):
    """Stub for TCP-like channels"""
    pass
