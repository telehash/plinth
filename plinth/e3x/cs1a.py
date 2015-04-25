# -*- coding: utf-8 -*-

from tomcrypt import ecc
from tomcrypt.hash import sha256
from tomcrypt.cipher import aes


def local_new():
    return ecc.Key(160)

def local_decrypt(local_key, packet):
    pass
def local_sign():
    pass
def remote_encrypt():
    pass
def remote_validate():
    pass
def ephemeral_encrypt():
    pass
def ephemeral_decrypt():
    pass


class CS1a(object):
    pass

"""
  ret->local_new = (void *(*)(lob_t, lob_t))local_new;
  ret->local_free = (void (*)(void *))local_free;
  ret->local_decrypt = (lob_t (*)(void *, lob_t))local_decrypt;
  ret->local_sign = (lob_t (*)(void *, lob_t, uint8_t *, size_t))local_sign;
  ret->remote_new = (void *(*)(lob_t, uint8_t *))remote_new;
  ret->remote_free = (void (*)(void *))remote_free;
  ret->remote_verify = (uint8_t (*)(void *, void *, lob_t))remote_verify;
  ret->remote_encrypt = (lob_t (*)(void *, void *, lob_t))remote_encrypt;
  ret->remote_validate = (uint8_t (*)(void *, lob_t, lob_t, uint8_t *, size_t))remote_validate;
  ret->ephemeral_new = (void *(*)(void *, lob_t))ephemeral_new;
  ret->ephemeral_free = (void (*)(void *))ephemeral_free;
  ret->ephemeral_encrypt = (lob_t (*)(void *, lob_t))ephemeral_encrypt;
  ret->ephemeral_decrypt = (lob_t (*)(void *, lob_t))ephemeral_decrypt;
"""

