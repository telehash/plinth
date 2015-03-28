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

class CipherSet(object):
    def __init__(self, secret):
    def local_new():
        pass
    def local_decrypt():
        pass
    def local_sign():
        pass
    def remote_encrypt():
        pass
    def remote_validate():
        pass
    def ephemeral_encrypt():
        pass
    def ephemeral_decrypt()
        pass

