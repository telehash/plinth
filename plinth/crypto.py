# -*- coding: utf-8 -*-

import os
import time
from tomcrypt.hash import sha256
from tomcrypt.cipher import aes

from . import packet
from .identity import SwitchID
from .log import log


def read_open(me, sender_ecc, wrapper, payload):
    aes_key = sha256(sender_ecc)
    sig_test = sha256(payload).digest()
    iv = wrapper['iv'].decode('hex')
    body = aes(aes_key.digest(), iv).decrypt(payload)
    inner, sender_rsa = packet.decode(body)
    remote = SwitchID(key=sender_rsa)
    if not all(k in inner for k in ('to', 'at', 'line')):
        raise PacketException('Malformed inner open')
    enc_sig = wrapper['sig'].decode('base64')
    line_id = inner['line'].decode('hex')
    aes_key.update(line_id)
    sig = aes(aes_key.digest(), iv).decrypt(enc_sig)
    if not remote.verify(sig_test, sig):
        raise PacketException('Invalid signature in open')
    if inner['to'] != me:
        raise PacketException('Open addressed to wrong hash_name?!')
    #TODO: validate these too
    return remote, line_id, inner['at']
