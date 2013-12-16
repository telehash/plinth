# -*- coding: utf-8 -*-

import os
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
