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
            addr = (seed['ip'], seed['port'])
            #block until ready or abort?
            line = Line(self.local, self.sendto, addr, remote)
            self.lines[line.id] = line
            self.known_hashes[hn] = line.id

    def incoming(self, (wrapper, payload)):
        """Hands off incoming packets to appropriate Lines"""
        t, iv = wrapper['type'], wrapper['iv']
        if t == 'line':
            l = wrapper['line']
            if l in self.lines:
                self.lines[l].recv(iv, payload)
        elif t == 'open':
            log.debug(wrapper)
            o = wrapper['open']
            log.debug("open b64 len: %s\nopen raw len: %s" % (len(o), len(o.decode('base64'))))
            ecc_key = self.local.decrypt(wrapper['open'])
            log.debug("DEB: %s" % ecc_key)
            aes_key = sha256(ecc_key)
            body = aes(aes_key.digest(), iv).decrypt(payload)
            inner, remote_rsa = packet.decode(body)
            remote = SwitchID(remote_rsa)
            hn = remote.hash_name
            log.debug('Got an open from %s' % hn)
            remote_line = inner['line'].decode('hex')
            aes_key.update(remote_line)
            candidate_line = self.known_hashes.get(hn, None)
            if candidate_line is not None:
                pass #We're waiting on this open...
            else:
                pass #Create a new line
            encrypted_sig = wrapper['sig'].decode('base64')
        else:
            pass #Fwomp
        

class Line(object):
    def __init__(self, local, sendto, addr, remote=None):
        """Create a bi-directional connection to a remote Switch.

        Probably not a fantastic idea to be doing so much in __init__
        but we'll figure that out later.
        """
        self._id = os.urandom(16)
        self._rid = None
        self.secret = None
        #TODO: multi-homing
        self.remote_iface = addr
        self.sendto = sendto
        if remote is None:
            #Insert _recv_open() when remote node is initiator.
            pass
        else:
            open_pkt = self._open(local, remote)
            self._send(open_pkt)
            #wait for response?

    @property
    def id(self):
        return self._id.encode('hex')

    @property
    def rid(self):
        return self._rid.encode('hex')

    #Consider moving this out of Line altogether?
    def _open(self, local, remote=None, incoming=None):
        inner = {
            'to'   : remote.hash_name,
            'at'   : int(time.time() * 1000),
            'line' : self.id.encode('hex')
        }
        pkt = packet.encode(inner, local.pub_key_der)
        temp_key = ecc.Key(256)
        #body = 
        return None
    
    def _send(self, body):
        pkt = {}
        iv = os.urandom(16)
        pkt['iv'] = iv.encode('hex')
        if body == 'open':
            pkt['type'] = 'open'
            # encrypt with temp key
            # sign it
            # add signature to json
        else:
            # encrypt with line key
            pass
        self.sendto(packet.encode(pkt), self.remote_iface)

    def recv(self, iv, pkt):
        log.debug("Received: %s" % iv)
