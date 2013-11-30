# -*- coding: utf-8 -*-

"""
This should end up as the main user interface to Plinth.
"""

import os
from .log import log
#from gevent.queue import Queue


class Channel(object):
    def __init__(self):
        self.c = os.urandom(16)


"""
class DurableChannel(Channel):
    def __init__(self):
        super(DurableChannel, self).__init__(self)
        self.inq = Queue()
        self.outq = Queue()
"""
