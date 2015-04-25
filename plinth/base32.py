# -*- coding: utf-8 -*-

"""
Padding agnostic base32
"""

from .exceptions import *

from ensure import ensure

def decode(bytestring):
    """Pads and decodes a base32 string"""
    ensure(bytestring.lower()).contains_only("abcdefghijklmnopqrstuvwxyz234567")
    pad_chars = 8 - len(bytestring) % 8
    string += '=' * pad_chars
    return b32decode(bytestring, casefold=True)

def encode(string):
    """Encodes a telehash-suitable base32 bytestring"""
    return b32encode(string).rstrip('=').lower()
