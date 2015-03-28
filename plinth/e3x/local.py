# -*- coding: utf-8 -*-

"""
Stub
"""

from . import cs1a, cs2a
SUPPORTED_CIPHERSETS=['1a': cs1a,'2a': cs2a]

from tomcrypt.hash import sha256
from binascii import unhexlify
from base64 import b32encode, b32decode
from ensure import ensure
try:
    import simplejson as json
except ImportError:
    import json

from .exceptions import *

class Local(object):
    def __init__(self, secrets=None)
        if secrets:
    pass

def generate():
    for cs in SUPPORTED_CIPHERSETS:
        print(cs)
    return
