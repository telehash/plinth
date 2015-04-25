# -*- coding: utf-8 -*-

"""
Stub
"""

from . import ciphers

from tomcrypt.hash import sha256
from binascii import unhexlify
from base64 import b32encode, b32decode
from ensure import ensure
try:
    import simplejson as json
except ImportError:
    import json

from ..exceptions import *

class Local(object):
    def __init__(self, secrets=None):
        if secrets:
            print('hello')
    pass

def generate():
    for csid, cs in ciphers.supported.items():
        print(csid)
        secret = cs.local_new()
        print(secret.as_string())
    return
