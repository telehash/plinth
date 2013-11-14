#!/usr/bin/env python
"""
An early "lightning" attempt at getting TeleHash crypto working in Python
"""

from local_vars import DEST_KEY, DEST_HASH, DEST_HOST, DEST_PORT
import os
import time
import socket
from struct import pack, unpack

from tomcrypt import rsa, ecc, cipher, hash
from tomcrypt.utils import pem_encode

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
outer_open['open'] = dest_key.encrypt(session_ecc_pub) \
                             .encode('base64').translate(None, '\n')
outer_open['iv'] = iv.encode('hex')

hasher.update(line_id)
sym_key = cipher.aes(key=hasher.digest(), iv=iv, mode='ctr')
"""
The current version of PyTomCrypt won't hash the message before signing
so we need to do this manually, but the underlying libTomCrypt still needs
to know which hashing algorithm was used to sign properly.
"""
hasher = hash.new('sha256', outer_body)
outer_open['sig'] = sym_key.encrypt(id_key.sign(hasher.digest(),
                                padding='v1.5', hash='sha256')) \
                           .encode('base64').translate(None, '\n')

# defaults to utf-8
outer_open_json = json.dumps(outer_open, separators=(',', ':'), sort_keys=True)

outer_len = len(outer_open_json)
outer_body_len = len(outer_body)

# magical C string packing
fmt_str = '!H' + str(outer_len) + 's' + str(outer_body_len) + 's'
outer_open_packet = pack(fmt_str, outer_len, outer_open_json, outer_body)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(outer_open_packet, (DEST_HOST, DEST_PORT))

received = sock.recv(1500)
fmt_str = '!H' + str(len(received)-2) + 's'
received_len, received_open_packet = unpack(fmt_str, received)

# being super reckless in the name reuse from here forward
outer_open = json.loads(received_open_packet[:received_len])
outer_body = received_open_packet[received_len:]

remote_iv = outer_open['iv'].decode('hex')
remote_ecc_key = id_key.decrypt(outer_open['open'].decode('base64'))
hasher = hash.new('sha256', remote_ecc_key)
sym_key = cipher.aes(key=hasher.digest(), iv=remote_iv, mode='ctr')
inner_received = sym_key.decrypt(outer_body)

fmt_str = '!H' + str(len(inner_received)-2) + 's'
inner_len, inner_open_packet = unpack(fmt_str, inner_received)
inner_open = json.loads(inner_open_packet[:inner_len])
inner_body = inner_open_packet[inner_len:]
remote_line = inner_open['line'].decode('hex')
hasher.update(remote_line)
sym_key = cipher.aes(key=hasher.digest(), iv=remote_iv, mode='ctr')
remote_sig = sym_key.decrypt(outer_open['sig'].decode('base64'))
hasher = hash.new('sha256', outer_body)
verified = dest_key.verify(hasher.digest(), remote_sig, padding='v1.5', hash='sha256')

line_secret = session_ecc.shared_secret(ecc.Key(remote_ecc_key))

hasher = hash.new('sha256', line_secret)
hasher.update(remote_line)
hasher.update(line_id)
dec_key = hasher.digest()

hasher = hash.new('sha256', line_secret)
hasher.update(line_id)
hasher.update(remote_line)
enc_key = hasher.digest()

#Okay, let's "do a line"

random_seek = os.urandom(32).encode('hex')
print("Seeking: %s" % random_seek)
channel_id = os.urandom(16).encode('hex')
line_iv = os.urandom(16)

payload = {}
payload['c'] = channel_id
payload['type'] = 'seek'
payload['seek'] = random_seek
payload['seq'] = 0
payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)

payload_len = len(payload_json)

fmt_str = '!H' + str(payload_len) + 's'
payload_packet = pack(fmt_str, payload_len, payload_json)

sym_key = cipher.aes(key=enc_key, iv=line_iv, mode='ctr')
line_body = sym_key.encrypt(payload_packet)

outer_line = {}
outer_line['type'] = 'line'
outer_line['line'] = remote_line.encode('hex')
outer_line['iv'] = line_iv.encode('hex')
outer_line_json = json.dumps(outer_line, separators=(',', ':'), sort_keys=True)

outer_line_len = len(outer_line_json)
line_body_len = len(line_body)

fmt_str = '!H' + str(outer_line_len) + 's' + str(line_body_len) + 's'
line_packet = pack(fmt_str, outer_line_len, outer_line_json, line_body)

sock.sendto(line_packet, (DEST_HOST, DEST_PORT))

received = sock.recv(1500)

fmt_str = '!H' + str(len(received)-2) + 's'
received_len, received_line_packet = unpack(fmt_str, received)

received_line = json.loads(received_line_packet[:received_len])

remote_line_iv = received_line['iv'].decode('hex')
sym_key = cipher.aes(key=dec_key, iv=remote_line_iv, mode='ctr')

received_line_body = sym_key.decrypt(received_line_packet[received_len:])
print(received_line)

fmt_str = '!H' + str(len(received_line_body)-2) + 's'
received_len, received_line_payload = unpack(fmt_str, received_line_body)

print(received_line_payload)
