# -*- coding: utf-8 -*-

import os
import time
from tomcrypt import ecc
from tomcrypt.hash import sha256
from tomcrypt.cipher import aes

from .packet import Packet
from .log import log
from .channels import Channel


class Line(object):
    def __init__(self):
        """A bidirectional encryption tunnel between two switches"""
        self._id = os.urandom(16)
        self._rid = None
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
        data, body = Packet.decode(aes(self.aes_dec, iv).decrypt(pkt))
        c = data['c']
        t = data.get('type', None)
        log.debug("Channel %s recv: %s" % (c, t))
        """
        candidate_channel = self.channels.get(c, None)
        if candidate_channel is not None:
            candidate_channel.recv(data, body)
        elif t == 'seek':
            channel = Channel(self, c, data, body)
            hn = data['seek']
            response = {
                'type': 'see',
                'see':  self._seek(hn),
                'end':  True
            }
            channel.send(response)
        elif t is not None:
            channel = Channel(self, c, data, body)
            self.channels[c] = channel
        #Fwomp
        """

    def send(self, data):
        iv = os.urandom(16)
        log.debug(data)
        pkt = Packet.encode(data, '')
        body = aes(self.aes_enc, iv).encrypt(pkt)
        wrapper = {
            'type': 'line',
            'line': self.rid,
            'iv':   iv.encode('hex')
        }
        #self.dht.sendto(packet.encode(wrapper, body), self.remote_iface)
