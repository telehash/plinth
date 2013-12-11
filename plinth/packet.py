# -*- coding: utf-8 -*-

"""
Packet handling helper functions for Telehash.

This will probably need to be refactored to use BytesIO for speed.
"""

from struct import pack, unpack
import struct
from collections import namedtuple
try:
    import simplejson as json
except ImportError:
    import json


# Maybe make this global...
class PacketException(ValueError):
    """There was an error encoding or decoding your packet."""


"""
The length header on all Telehash packets
! == network order
H == unsigned short
"""
hdr = struct.Struct('!H')


def decode(packet):
    """Takes a bytestring and returns a decoded 2-tuple"""
    packet_size = len(packet)
    if packet_size < hdr.size:
        raise PacketException('Length header larger than actual packet')

    wrapper_size = hdr.unpack_from(packet)[0]
    payload_size = packet_size - (hdr.size + wrapper_size)
    if payload_size < 0:
        raise PacketException('JSON wrapper truncated?')

    # Maybe this notation makes more sense when one uses shorter names.
    wrapper_json = packet[hdr.size:hdr.size+wrapper_size]
    if len(wrapper_json) == 0:
        wrapper = {}
    else:
        wrapper = json.loads(wrapper_json)
    payload = packet[packet_size-payload_size:]
    return wrapper, payload


def encode(wrapper, payload=''):
    """Returns a bytestring suitable for transmission over the wire"""
    wrapper_json = json.dumps(wrapper, separators=(',', ':'), sort_keys=True)
    wrapper_size = len(wrapper_json)
    packet = hdr.pack(wrapper_size) + wrapper_json + payload
    if len(packet) > 1400:
        raise PacketException('Encoded packet would be too large')
    return packet
