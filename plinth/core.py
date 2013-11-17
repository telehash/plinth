# -*- coding: utf-8 -*-

import os
import time
import socket
from struct import pack, unpack

from tomcrypt import rsa, ecc, cipher, hash
from tomcrypt.utils import pem_encode
from gevent.server import DatagramServer

from .log import log


class Switch(object):

    def __init__(self, hash_name=None, seeds=None):
        self.lines = None

        if isinstance(hash_name, (HashName)):
            self.hash_name = hash_name
        else:
            self.hash_name = HashName()

    def start(self, listen=None):
        if isinstance(listen, (int)):
            log.debug('Listening for open packets on port %s' % str(listen))
        log.debug('Just hanging out so far!')


class HashName(object):

    __attrs__ = ['key']

    def __init__(self, priv_key=None):
        if isinstance(priv_key, (str, unicode)):
            try:
                self.key = rsa.Key(priv_key)
            except:
                raise Exception('Invalid private key!')
        else:
            self.key = rsa.Key(2048)
