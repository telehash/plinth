# -*- coding: utf-8 -*-

"""
Stub
"""

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
    pass

class Exchange(object):
    pass

def generate():
    for cs in SUPPORTED_CIPHERSETS:
        print(cs)
    return
