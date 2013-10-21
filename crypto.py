#!/usr/bin/env python
"""
An early "lightning" attempt at getting TeleHash crypto working in Python
"""

from local_vars import DEST_KEY, DEST_HASH
import os
from struct import pack, unpack
from tomcrypt import rsa, ecc, cipher, hash
import Crypto.Signature.PKCS1_v1_5 as PKCS
import Crypto.Hash.SHA256 as SHA256
import Crypto.PublicKey.RSA as RSA
import time

def epoch_milli():
    return int(time.time() * 1000)


try: import simplejson as json
except ImportError: import json

try:
    id_key = rsa.Key(open('id_key').read())
except:
    with open('id_key', 'w') as f:
        id_key = rsa.Key(2048)
        f.write(id_key.as_string())


id_key_pub = id_key.public.as_string(format='der')

dest_key = rsa.Key(DEST_KEY)

session_ecc = ecc.Key(256)
session_ecc_pub = session_ecc.public.as_string(format='der', ansi=True)

iv = os.urandom(16)
line_id = os.urandom(16)

inner_open = {}
inner_open['to'] = DEST_HASH
inner_open['at'] = epoch_milli()
inner_open['line'] = line_id.encode('hex')

# TODO: refactor into packet encoding function
# ---------------
# defaults to utf-8
inner_open_json = json.dumps(inner_open, separators=(',', ':'), sort_keys=True)

inner_len = len(inner_open_json)
id_key_len = len(id_key_pub)

# magical C string packing
fmt_str = '!H' + str(inner_len) + 's' + str(id_key_len) + 's'
inner_open_packet = pack(fmt_str, inner_len, inner_open_json, id_key_pub)
# ---------------

hasher = hash.new('sha256', session_ecc_pub)
sym_key = cipher.aes(key=hasher.digest(), iv=iv, mode='ctr')
outer_body = sym_key.encrypt(inner_open_packet)

outer_open = {}
outer_open['type'] = 'open'
outer_open['open'] = dest_key.encrypt( #encrypted to recipient
            session_ecc.public.as_string(format='der',ansi=True) #ANSI X9.63
            ).encode('base64').translate(None, '\n')
outer_open['iv'] = iv.encode('hex')

hasher.update(line_id)
sym_key = cipher.aes(key=hasher.digest(), iv=iv, mode='ctr')
"""
The default padding for pytomcrypt's rsa sign() is pss. The node implementation
uses the older PKCS1 padding ('v1.5' in pytomcrypt) but that setting segfaults
when I try it here. Updating the node implementation to use PSS padding doesn't
seem to help anything either.
"""

id_key_new = RSA.importKey(id_key.as_string())
hash_new = SHA256.new(outer_body)
pkcs_new = PKCS.new(id_key_new)
sig_new = pkcs_new.sign(hash_new)

outer_open['sig'] = sym_key.encrypt(sig_new).encode('base64').translate(None, '\n')

#outer_open['sig'] = sym_key.encrypt(id_key.sign(outer_body, hash='sha256')) \
#                           .encode('base64').translate(None, '\n')

# defaults to utf-8
outer_open_json = json.dumps(outer_open, separators=(',', ':'), sort_keys=True)

outer_len = len(outer_open_json)
id_key_len = len(id_key_pub)

print(outer_open_json + '\n')
print(outer_body.encode('hex') +'\n')
