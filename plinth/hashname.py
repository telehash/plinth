# -*- coding: utf-8 -*-

"""
Implements hashname encoding / validation
"""

from . import base32
from tomcrypt.hash import sha256
from binascii import unhexlify
from base64 import b32encode, b32decode
from ensure import ensure
try:
    import simplejson as json
except ImportError:
    import json

def fromKeys(keys):
    ensure(keys).is_a(dict)
    rollup = u''
    for k,v in sorted(keys.items()):
        cs = ord(unhexlify(k))
        ensure(cs).is_greater_than(0)
        ensure(cs).is_less_than(256)
        rollup = sha256(rollup + chr(cs)).digest()
        intermediate = sha256(base32.decode(v)).digest()
        rollup = sha256(rollup + intermediate).digest()
    return base32.encode(rollup)
