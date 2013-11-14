# -*- coding: utf-8 -*-

import os
import time
import logging
import socket
from struct import pack, unpack

from tomcrypt import rsa, ecc, cipher, hash
from tomcrypt.utils import pem_encode

log = logging.getLogger(__name__)

class Switch(object):

    __attrs__ = [ 'priv_key', 'pub_key' ]

    def __init__(self, key=None):

        if isinstance(key, (str, unicode)):
            try:
                self.priv_key = rsa.Key(key)
            except:
                raise Exception('Invalid private key!')
        else:
            self.priv_key = rsa.Key(2048)

        self.pub_key = self.priv_key.public

    def run(self, port=42424):
        log.debug(self.pub_key.as_string())
        log.debug('Stub!')
