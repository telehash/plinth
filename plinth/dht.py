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
        self.kbucket = []
        self.known_hashes = {}
        self.lines = {}

    def start(self):
        for seed in self.seeds:
            remote = SwitchID(hash_name=seed['hashname'],
                              key=seed['pubkey'])
            hn = remote.hash_name
            address = (seed['ip'], seed['port'])
            #block until ready or abort?
            line = Line(self, address, remote)
            self.lines[line.id] = line
            self.known_hashes[hn] = (line.id, address, remote)
        self.maintain()

    def recv(self, wrapper, payload, address):
        """Hands off incoming packets to appropriate Lines"""
        t, iv = wrapper['type'], wrapper['iv'].decode('hex')
        if t == 'line':
            l = wrapper['line']
            if l in self.lines:
                #Passing self in for seeks... Feels icky this way.
                self.lines[l].recv(iv, payload, self)
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
            candidate_line, __ , __ = self.known_hashes.get(hn, (None,None,None))
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
                line = Line(self, address, remote, secrets)
                self.lines[line.id] = line
                self.known_hashes[hn] = (line.id, address, remote)
        else:
            pass  # Fwomp

    def maintain(self):
        pass

    def seek(self, switch):
        see_list = []
        hn = switch.hash_name
        bkt = self.local.kdist(switch)
        log.debug("%s in bucket: %s" % (hn, bkt))
        if hn in self.known_hashes:
            ip, port = self.known_hashes[hn][1]
            see = ','.join((hn,ip,str(port)))
            see_list.append(see)
        return see_list

class Line(object):
    def __init__(self, dht, addr, remote, secrets=None):
        """Create a bi-directional connection to a remote Switch.

        Probably not a fantastic idea to be doing so much in __init__
        but we'll figure that out later.
        """
        self.dht = dht
        self._id = os.urandom(16)
        self._rid = None
        self._ecc_key = None
        self.secret = None
        #TODO: multi-homing
        self.remote_iface = addr
        self.channels = {}
        self._open(remote, secrets)

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
    def _open(self, remote, secrets=None):
        inner = {
            'to':   remote.hash_name,
            'at':   int(time.time() * 1000),
            'line': self.id
        }
        body = packet.encode(inner, self.dht.local.pub_key_der)
        self._ecc_key = ecc.Key(256)
        ecc_key_pub = self._ecc_key.public.as_string(format='der', ansi=True)
        aes_key = sha256(ecc_key_pub)
        iv = os.urandom(16)
        encrypted_body = aes(aes_key.digest(), iv).encrypt(body)
        sig = self.dht.local.sign(sha256(encrypted_body).digest())
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
        self.dht.sendto(packet.encode(outer, encrypted_body), self.remote_iface)

    def _seek(self, hn):
        switch = SwitchID(hash_name=hn)
        return self.dht.seek(switch)

    def ecdh(self, (remote_line, remote_ecc_key)):
        self._rid = remote_line
        self.secret = self._ecc_key.shared_secret(ecc.Key(remote_ecc_key))
        log.debug('ECDH: %s' % self.secret.encode('hex'))
        #Throw it away!
        del self._ecc_key

    def recv(self, iv, pkt, dht):
        data, body = packet.decode(aes(self.aes_dec, iv).decrypt(pkt))
        c = data['c']
        t = data.get('type', None)
        candidate_channel = self.channels.get(c, None)
        if candidate_channel is not None:
            candidate_channel.recv(data, body)
        elif t == 'seek':
            channel = Channel(self, c, data, body)
            hn = data['seek']
            response = {
                'type': 'see',
                'see':  self._seek(hn),
                'end':  True
            }
            channel.send(response)
        elif t is not None:
            channel = Channel(self, c, data, body)
            self.channels[c] = channel
        #Fwomp

    def send(self, data):
        iv = os.urandom(16)
        log.debug(data)
        pkt = packet.encode(data, '')
        body = aes(self.aes_enc, iv).encrypt(pkt)
        wrapper = {
            'type': 'line',
            'line': self.rid,
            'iv':   iv.encode('hex')
        }
        self.dht.sendto(packet.encode(wrapper, body), self.remote_iface)
