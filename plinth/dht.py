# -*- coding: utf-8 -*-

from bitarray import bitarray, bitdiff
import os
import time
from tomcrypt import ecc
from tomcrypt.hash import sha256
from tomcrypt.cipher import aes

from . import packet
from .log import log
from .identity import SwitchID
from .channels import Channel


class DHT(object):
    """Manages information about remote Switches and Lines"""
    def __init__(self, local, inq, sendto, seeds):
        self.local = local
        self.sendto = sendto
        self.seeds = seeds
        self.inq = inq
        self.kbuckets = {}
        self.known_hashes = {}
        self.lines = {}

    def start(self):
        for seed in self.seeds:
            remote = SwitchID(hash_name=seed['hashname'],
                              key=seed['pubkey'])
            hn = remote.hash_name
            address = (seed['ip'], seed['port'])
            #block until ready or abort?
            line = Line(self.local, self.sendto, address, remote)
            self.lines[line.id] = line
            self.known_hashes[hn] = line.id

    def incoming(self, wrapper, payload, address):
        """Hands off incoming packets to appropriate Lines"""
        t, iv = wrapper['type'], wrapper['iv'].decode('hex')
        if t == 'line':
            l = wrapper['line']
            if l in self.lines:
                self.lines[l].recv(iv, payload)
        elif t == 'open':
            remote_ecc_key = self.local.decrypt(wrapper['open'])
            aes_key = sha256(remote_ecc_key)
            body = aes(aes_key.digest(), iv).decrypt(payload)
            inner, remote_rsa = packet.decode(body)
            remote = SwitchID(key=remote_rsa)
            hn = remote.hash_name
            log.debug('Received open from %s' % hn)
            remote_line = inner['line'].decode('hex')
            aes_key.update(remote_line)
            candidate_line = self.known_hashes.get(hn, None)
            encrypted_sig = wrapper['sig'].decode('base64')
            sig = aes(aes_key.digest(), iv).decrypt(encrypted_sig)
            secrets = (remote_line, remote_ecc_key)
            if not remote.verify(sha256(payload).digest(), sig):
                log.debug('Invalid signature from: %s' % hn)
                return
            if candidate_line is not None:
                log.debug('Open for existing Line: %s' % candidate_line)
                line = self.lines[candidate_line]
                if line.secret is None:
                    line.ecdh(secrets)
            else:
                line = Line(self.local, self.sendto, address, remote, secrets)
                self.lines[line.id] = line
                self.known_hashes[hn] = line.id
        else:
            pass  # Fwomp


class Line(object):
    def __init__(self, local, sendto, addr, remote, secrets=None):
        """Create a bi-directional connection to a remote Switch.

        Probably not a fantastic idea to be doing so much in __init__
        but we'll figure that out later.
        """
        self._id = os.urandom(16)
        self._rid = None
        self._ecc_key = None
        self.secret = None
        #TODO: multi-homing
        self.remote_iface = addr
        self.sendto = sendto
        self.channels = {}
        self._open(local, remote, secrets)

    @property
    def id(self):
        return self._id.encode('hex')

    @property
    def rid(self):
        return self._rid.encode('hex')

    @property
    def aes_dec(self):
        return sha256(self.secret + self._rid + self._id).digest()

    @property
    def aes_enc(self):
        return sha256(self.secret + self._id + self._rid).digest()

    #Consider moving this out of Line altogether?
    def _open(self, local, remote, secrets=None):
        inner = {
            'to':   remote.hash_name,
            'at':   int(time.time() * 1000),
            'line': self.id
        }
        body = packet.encode(inner, local.pub_key_der)
        self._ecc_key = ecc.Key(256)
        ecc_key_pub = self._ecc_key.public.as_string(format='der', ansi=True)
        aes_key = sha256(ecc_key_pub)
        iv = os.urandom(16)
        encrypted_body = aes(aes_key.digest(), iv).encrypt(body)
        sig = local.sign(sha256(encrypted_body).digest())
        aes_key.update(self._id)
        encrypted_sig = aes(aes_key.digest(), iv).encrypt(sig)
        outer = {
            'type': 'open',
            'open': remote.encrypt(ecc_key_pub),
            'iv':   iv.encode('hex'),
            'sig':  encrypted_sig.encode('base64').translate(None, '\n')
        }
        log.debug('Sending open to: %s' % remote.hash_name)
        if secrets is not None:
            self.ecdh(secrets)
        self.sendto(packet.encode(outer, encrypted_body), self.remote_iface)

    def ecdh(self, (remote_line, remote_ecc_key)):
        self._rid = remote_line
        self.secret = self._ecc_key.shared_secret(ecc.Key(remote_ecc_key))
        log.debug('ECDH: %s' % self.secret.encode('hex'))
        #Throw it away!
        del self._ecc_key

    def recv(self, iv, pkt):
        data, body = packet.decode(aes(self.aes_dec, iv).decrypt(pkt))
        c = data['c']
        t = data.get('type', None)
        candidate_channel = self.channels.get(c, None)
        if candidate_channel is not None:
            candidate_channel.incoming(data, body)
        if t is not None:
            channel = Channel(c, data, body)
            self.channels[c] = channel
