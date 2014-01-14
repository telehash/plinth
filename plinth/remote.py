# -*- coding: utf-8 -*-

import os
import time
from collections import defaultdict
from operator import itemgetter

import gevent
from tomcrypt import ecc
from tomcrypt.hash import sha256
from tomcrypt.cipher import aes

from .log import log
from .identity import SwitchID
from .packet import Packet
from .line import Line
from .channel import Channel
from .exceptions import *


class RemoteSwitch(object):
    def __init__(self, switch_id, dht):
        self.id = switch_id
        self.local_id = dht.me
        self.transmit = dht.transmit
        self.dht = dht
        self.line = None
        self.line_time = 0
        self.channels = {}
        self.paths = defaultdict(lambda: 0)

    def _ecdh(self, remote_line, remote_ecc):
        secret = self._ecc.shared_secret(ecc.Key(remote_ecc))
        log.debug('ECDH: %s' % secret.encode('hex'))
        #safe to remove this; keep _ecc_pub for open retransmits
        del self._ecc
        self.line.complete(remote_line, secret)

    def path_hint(self, paths):
        for path in paths:
            t = path.get('type')
            if t == 'ipv4':
                ip = path.get('ip')
                port = path.get('port')
                pri = path.get('priority', 0)
                self.paths[(ip,port)] += pri

    def best_path(self):
        ranked = sorted(self.paths.iteritems(), key=itemgetter(1))
        if ranked:
            return ranked[0][0]
        else:
            return None

    def confirm_path(self, address):
        self.paths[address] = time.time() * 1000

    def start(self):
        if self.line:
            pass
        else:
            if self.id.known:
                gevent.spawn(self.new_line)
            else:
                log.debug('TODO: recursive seek/peer')

    def new_line(self, retry=2):
        """Creates or replaces a secure line to the remote switch"""
        if self.line:
            log.debug('Invalidating previous line: %s' % self.line.id)
            #unregister Line dangerously
            del self.dht.linemap[self.line.id]
            del self.line
        self.line = Line()
        self.dht.linemap[self.line.id] = self
        """
        In order to separate the concerns, you have to mix them up first,
        right? The "at" timestamp in an "open" packet signifies the time
        that the local ECC key was generated. That local ECC key only
        needs to be kept around if we haven't received a remote "open"
        packet. I'll try to make this connection clearer in the next
        big refactor.
        """
        self._ecc = ecc.Key(256)
        self._ecc_pub = self._ecc.public \
                            .as_string(format='der', ansi=True)
        self._open = Packet.create_open(
            self.id.hash_name,
            self.line.id,
            self.local_id.pub_key_der)
        self._send_open()
        retried = 0
        while retried < retry:
            gevent.sleep(1)
            if self.line.is_complete:
                break
            self._send_open()
            retried += 1
            log.debug('open retry %i' % retried)

    def send(self, data, timeout=5):
        """Take a Channel packet, wrap it in a line, and send

        TODO: implement timeout to wait for line
        """
        if not self.line:
            log.debug('TODO: fix send without line')
            return
        if self.line.is_complete:
            self._send(self.line.send(data))
        else:
            gevent.sleep(1)
            if self.line.is_complete:
                self._send(self.line.send(data))
            else:
                log.debug('Brutally dropping packets until line is up.')

    def _send(self, data):
        """Transmit packet on best network path"""
        address = self.best_path()
        log.debug('Sending %s to %s' % (len(data), address))
        self.transmit(data, address)

    def recv(self, p, address):
        self.confirm_path(address)
        if not self.line.is_complete:
            log.debug('Quick restart, remote line still open?')
            log.debug('Hashname: %s' % self.id.hash_name)
            return
        data, body = self.line.recv(p.iv, p.payload)
        c = data.get('c')
        if c is None:
            #ideally push this kind of validation into the Packet class
            return
        candidate = self.channels.get(c)
        if candidate is None:
            t = data.get('type')
            if not isinstance(t, (str, unicode)):
                return
            ch = Channel.incoming(self, t, c, data, body)
            self.channels[c] = ch
        else:
            candidate.recv(data, body)

    def _send_open(self):
        iv = os.urandom(16)
        aes_key = sha256(self._ecc_pub)
        enc_body = aes(aes_key.digest(), iv).encrypt(self._open)
        aes_key.update(self.line.id.decode('hex'))
        sig = self.local_id.sign(sha256(enc_body).digest())
        enc_sig = aes(aes_key.digest(), iv).encrypt(sig)
        o = self.id.encrypt(self._ecc_pub)
        data = Packet.wrap_open(o, iv, enc_sig, enc_body)
        self._send(data)
        log.debug('Open to: %s' % self.id.hash_name)
        log.debug('Line: %s to %s' % (self.line.id, self.line.rid))

    def handle_open(self, p, address):
        """Deal with incoming open from this remote switch"""
        self.confirm_path(address)
        log.debug('Open from: %s' % self.id.hash_name)
        if self.line:
            #We're expecting this or we might need to invalidate?
            log.debug('Line: %s from %s' % (self.line.id, self.line.rid))
            log.debug('At: %i' % (p.at))
        if self.line and self.line_time == 0:
            #we've been waiting for our first open
            self.line_time = p.at
        if self.line_time < p.at:
            self.new_line(retry=0)
            self._ecdh(p.line, p.ecc)
            return
        if self.line.is_complete:
            #remote didn't get our response open
            self._send_open()
        else:
            self._ecdh(p.line, p.ecc)

    def open_channel(self, ctype, initial_data):
        ch = Channel.outgoing(self, ctype)
        self.channels[ch.c] = ch
        ch.start(initial_data)
        return ch
