# -*- coding: utf-8 -*-

"""
Packet handling helper functions for Telehash.

This will probably need to be refactored to use BytesIO for speed.
"""

import time
import struct

from tomcrypt import ecc
from tomcrypt.hash import sha256
from tomcrypt.cipher import aes

from .log import log
from .identity import SwitchID
from .exceptions import *

try:
    import simplejson as json
except ImportError:
    import json


class Packet(object):
    """TeleHash Packet validation / handling"""

    # TeleHash length header: !H == network order, unsigned short
    hdr = struct.Struct('!H')

    def __init__(self, data):
        """Basic validation to start

        TODO: Look at enum or namedtuple / similar structures.
        """
        wrapper, self.payload = self.decode(data)
        if 'type' not in wrapper:
            raise PacketException('Missing type')
        t = wrapper['type']
        if 'iv' not in wrapper:
            raise PacketException('Missing iv')
        self.iv = wrapper['iv'].decode('hex')
        if t not in ('line', 'open'):
            raise PacketException('Unknown packet type')
        if t not in wrapper:
            raise PacketException('Missing open/line value')
        elif t == 'line':
            self.line = wrapper[t]
            self.open = False
        elif t == 'open':
            self.open = wrapper[t]
            if 'sig' not in wrapper:
                raise PacketException('Missing signature in open')
            self.enc_sig = wrapper['sig'].decode('base64')
        self.t = t

    def read_open(self, me, sender_ecc):
        """Decode this received open packet"""
        self.ecc = sender_ecc
        aes_key = sha256(self.ecc)
        sig_test = sha256(self.payload).digest()
        body = aes(aes_key.digest(), self.iv).decrypt(self.payload)
        inner, sender_rsa = self.decode(body)
        remote = SwitchID(key=sender_rsa)
        if not all(k in inner for k in ('to', 'at', 'line')):
            raise PacketException('Malformed inner open')
        self.line = inner['line'].decode('hex')
        aes_key.update(self.line)
        sig = aes(aes_key.digest(), self.iv).decrypt(self.enc_sig)
        if not remote.verify(sig_test, sig):
            raise PacketException('Invalid signature in open')
        if inner['to'] != me:
            raise PacketException('Open addressed to wrong hash_name?!')
        #TODO: validate these too
        self.at = inner['at']
        return remote

    @classmethod
    def create_open(cls, to_hash, line_id, pub_key):
        inner = {
            'to': to_hash,
            'at': int(time.time() * 1000),
            'line': line_id
        }
        return cls.encode(inner, pub_key)

    @classmethod
    def wrap_open(cls, o, iv, sig, body):
        outer = {
            'type': 'open',
            'open': o,
            'iv':   iv.encode('hex'),
            'sig':  sig.encode('base64').translate(None, '\n')
        }
        return cls.encode(outer, body)

    @classmethod
    def wrap_line(cls, l, iv, body):
        outer = {
            'type': 'line',
            'line': l,
            'iv':   iv.encode('hex')
        }
        return cls.encode(outer, body)

    @classmethod
    def decode(cls, packet):
        """Takes a bytestring and returns a decoded 2-tuple"""
        s = cls.hdr.size
        packet_size = len(packet)
        if packet_size < s:
            raise PacketException('Length header larger than actual packet')

        wrapper_size = cls.hdr.unpack_from(packet)[0]
        payload_size = packet_size - (s + wrapper_size)
        if payload_size < 0:
            raise PacketException('JSON wrapper truncated?')

        wrapper_json = packet[s:s+wrapper_size]
        if len(wrapper_json) == 0:
            wrapper = None
        else:
            wrapper = json.loads(wrapper_json)
        payload = packet[packet_size-payload_size:]
        return wrapper, payload

    @classmethod
    def encode(cls, wrapper, payload=''):
        """Returns a bytestring suitable for transmission over the wire"""
        wrapper_json = json.dumps(wrapper,
                                  separators=(',', ':'),
                                  sort_keys=True)
        wrapper_size = len(wrapper_json)
        packet = cls.hdr.pack(wrapper_size) + wrapper_json + payload
        if len(packet) > 1400:
            raise PacketException('Encoded packet would be too large')
        return packet
