# -*- coding: utf-8 -*-

"""
This should end up as the main user interface to Plinth.
"""

import os
from .log import log
#from gevent.queue import Queue


class Channel(object):
    def __init__(self, line, c=None, data=None, body=None):
        self.line = line
        self.c = c
        if self.c is None:
            self.c = os.urandom(16)
        if data is not None:
            self.recv(data, body)

    def recv(self, data, body):
        log.debug('Received on Channel: %s' % self.c)
        log.debug(data)

    def send(self, data):
        data['c'] = self.c
        log.debug("sending: %s" % data)
        self.line.send(data)

"""
class DurableChannel(Channel):
    def __init__(self):
        super(DurableChannel, self).__init__(self)
        self.inq = Queue()
        self.outq = Queue()
"""
