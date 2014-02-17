# -*- coding: utf-8 -*-

import os
import time
from tomcrypt.hash import sha256
from tomcrypt.cipher import aes

from . import packet
from .log import log


class Line(object):
    def __init__(self):
        """A bidirectional encryption tunnel between two switches"""
        self._id = os.urandom(16)
        self._rid = '\0'
        self.secret = None

    @property
    def id(self):
        return self._id.encode('hex')

    @property
    def rid(self):
        return self._rid.encode('hex')

    @property
    def aes_dec(self):
        return sha256(self.secret + self._rid + self._id).digest()

    @property
    def aes_enc(self):
        return sha256(self.secret + self._id + self._rid).digest()

    @property
    def is_complete(self):
        if self.secret is None:
            return False
        else:
            return True

    def complete(self, remote_line, secret):
        self._rid = remote_line
        self.secret = secret

    def recv(self, iv, pkt):
        data, body = packet.decode(aes(self.aes_dec, iv).decrypt(pkt))
        return data, body

    def send(self, data, body=''):
        iv = os.urandom(16)
        log.debug('Sending on Line %s:' % self.id)
        log.debug(data)
        payload = packet.encode(data, body)
        enc_payload = aes(self.aes_enc, iv).encrypt(payload)
        return packet.wrap_line(self.rid, iv, enc_payload)
