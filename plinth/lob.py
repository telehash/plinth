# -*- coding: utf-8 -*-

"""
Implements Length-Object-Binary format
"""

import struct

from .exceptions import *

try:
    import simplejson as json
except ImportError:
    import json


# !H == network order, unsigned short
length_header = struct.Struct('!H') # 2 bytes

def decode(packet):
    """Takes a bytestring and returns a decoded LOB 5-tuple"""
    packet_size = len(packet)
    if packet_size < 2:
        raise PacketException('Packet too small')

    head_len = length_header.unpack_from(packet)[0]
    body_len = packet_size - (2 + head_len)
    if body_len < 0:
        raise PacketException('JSON wrapper truncated?')

    head = packet[2:2+head_len]
    head_json = None
    head_bin = None
    if len(head) > 7:
        head_json = json.loads(head)
    elif len(head) > 0:
        head_bin = head
    body = packet[packet_size-body_len:]
    return head_len, head_bin, head_json, body_len, body

def encode(head, body=''):
    """Returns a bytestring suitable for transmission over the wire"""
    head_json = json.dumps(wrapper,
                           separators=(',', ':'),
                           sort_keys=True)
    head_len = len(head_json)
    packet = length_header.pack(head_len) + head_json + body
    if len(packet) > 1400:
        raise PacketException('Encoded packet needs chunking')
    return packet

