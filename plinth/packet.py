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


# !H == network order, unsigned short
length_header = struct.Struct('!H')

def decode(packet):
    """Takes a bytestring and returns a decoded 2-tuple"""
    s = length_header.size
    packet_size = len(packet)
    if packet_size < s:
        raise PacketException('Length header larger than actual packet')

    wrapper_size = length_header.unpack_from(packet)[0]
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

def encode(wrapper, payload=''):
    """Returns a bytestring suitable for transmission over the wire"""
    wrapper_json = json.dumps(wrapper,
                              separators=(',', ':'),
                              sort_keys=True)
    wrapper_size = len(wrapper_json)
    packet = length_header.pack(wrapper_size) + wrapper_json + payload
    if len(packet) > 1400:
        raise PacketException('Encoded packet would be too large')
    return packet

def wrap_open(o, iv, sig, body):
    outer = {
        'type': 'open',
        'open': o,
        'iv':   iv.encode('hex'),
        'sig':  sig.encode('base64').translate(None, '\n')
    }
    return encode(outer, body)

def wrap_line(l, iv, body):
    outer = {
        'type': 'line',
        'line': l,
        'iv':   iv.encode('hex')
    }
    return encode(outer, body)

def create_open(to_hash, line_id, pub_key):
    inner = {
        'to': to_hash,
        'at': int(time.time() * 1000),
        'line': line_id
    }
    return encode(inner, pub_key)

def validate_wrapper(wrapper):
    if 'iv' not in wrapper:
        raise PacketException('Missing iv')
    if 'type' not in wrapper:
        raise PacketException('Missing type')
    t = wrapper['type']
    if t not in ('line', 'open'):
        raise PacketException('Unknown packet type')
    if t not in wrapper:
        raise PacketException('Missing open/line value')
    if t == 'open':
        if 'sig' not in wrapper:
            raise PacketException('Missing signature in open')
    return t
