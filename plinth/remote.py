# -*- coding: utf-8 -*-

import os
import time
from collections import defaultdict
from operator import itemgetter

import gevent
from gevent.queue import Queue
from gevent.event import Event
from tomcrypt import ecc
from tomcrypt.hash import sha256
from tomcrypt.cipher import aes

from .log import log
from .identity import SwitchID
from . import packet
from .line import Line
from .channel import Channel, DurableChannel
from .exceptions import *


class RemoteSwitch(gevent.Greenlet):
    def __init__(self, switch_id, dht):
        super(RemoteSwitch, self).__init__()
        self.id = switch_id
        self.local_id = dht.me
        self.transmit = dht.transmit
        self.dht = dht
        self.line = None
        self.line_time = 0
        self.channels = {}
        self.paths = defaultdict(lambda: 0)
        self.packetq = Queue()
        self.openq = Queue()

    def _run(self):
        self.running = True
        #TODO: This might be a bad way to green-sublet
        gevent.spawn(self.open_handler)
        while self.running:
            wrapper, payload, address = self.packetq.get()
            self.recv(wrapper, payload, address)
            gevent.sleep(0)

    def open_handler(self):
        while self.running:
            open_tuple = self.openq.get()
            self.handle_open(open_tuple)
            gevent.sleep(0)

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
                self.paths[(ip, port)] += pri

    def best_path(self):
        ranked = sorted(self.paths.iteritems(), key=itemgetter(1))
        if ranked:
            return ranked[0][0]
        else:
            return None

    def all_paths(self):
        #more terrible ipv4 stopgap stuff
        paths_array = []
        for path, pri in self.paths.iteritems():
            if pri > 0:
                valid_path = {'type': 'ipv4'}
                valid_path['ip'] = path[0]
                valid_path['port'] = path[1]
                paths_array.append(valid_path)
        log.debug('PATHS ARRAY: {}'.format(paths_array))
        return paths_array

    def confirm_path(self, address):
        self.paths[address] = time.time() * 1000

    def new_line(self):
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
        self._open = packet.create_open(
            self.id.hash_name,
            self.line.id,
            self.local_id.pub_key_der)
        self._send_open()

    def send(self, data, body='', timeout=5):
        """Take a Channel packet, wrap it in a line, and send

        TODO: implement timeout to wait for line
        """
        if not self.line:
            l = gevent.spawn(self.new_line)
            l.join(timeout)
            if l.successful():
                pass
            else:
                log.debug('line timeout')
                return
        if self.line.is_complete:
            self._send(self.line.send(data, body))
        else:
            gevent.sleep(1)
            if self.line.is_complete:
                self._send(self.line.send(data, body))
            else:
                log.debug('Brutally dropping packets until line is up.')

    def _send(self, data):
        """Transmit packet on best network path"""
        address = self.best_path()
        log.debug('Sending %s to %s' % (len(data), address))
        self.transmit(data, address)

    def recv(self, wrapper, payload, address):
        self.confirm_path(address)
        if not self.line.is_complete:
            log.debug('Quick restart, remote line still open?')
            log.debug('Hashname: %s' % self.id.hash_name)
            return
        iv = wrapper['iv'].decode('hex')
        data, body = self.line.recv(iv, payload)
        c = data.get('c')
        if c is None:
            return
        candidate = self.channels.get(c)
        if candidate is None:
            t = data.get('type')
            if not isinstance(t, (str, unicode)):
                return
            if t[:1] != '_':
                ch = Channel(self, t, c)
                self.dht.channel_handler(self, ch, data, body)
            elif 'seq' in data.keys():
                ch = DurableChannel(self, t, c)
            else:
                #TODO: get remote-initiated channel handler from user
                ch = Channel(self, t, c)
                self.channels[c] = ch
        else:
            candidate.inq.put((data, body))

    def _send_open(self):
        iv = os.urandom(16)
        aes_key = sha256(self._ecc_pub)
        enc_body = aes(aes_key.digest(), iv).encrypt(self._open)
        aes_key.update(self.line.id.decode('hex'))
        sig = self.local_id.sign(sha256(enc_body).digest())
        enc_sig = aes(aes_key.digest(), iv).encrypt(sig)
        o = self.id.encrypt(self._ecc_pub)
        data = packet.wrap_open(o, iv, enc_sig, enc_body)
        self._send(data)
        log.debug('Open to: %s' % self.id.hash_name)
        log.debug('Line: %s to %s' % (self.line.id, self.line.rid))

    def handle_open(self, open_tuple):
        """Deal with incoming open from this remote switch"""
        # getting quick and dirty again for a bit
        #sender_ecc, line_id, at, address = open_tuple
        self.confirm_path(open_tuple[3])
        log.debug('Open from: %s' % self.id.hash_name)
        recv_at = open_tuple[2]
        while not self.openq.empty():
            # pick any single open with the latest timestamp
            cand_tuple = self.openq.get()
            sender_ecc, line_id, at, address = open_tuple
            self.confirm_path(cand_tuple[3])
            if cand_tuple[2] > recv_at:
                open_tuple = cand_tuple
        sender_ecc, line_id, at, address = open_tuple
        if self.line:
            #We're expecting this or we might need to invalidate?
            log.debug('Line: %s from %s' % (self.line.id, self.line.rid))
            log.debug('At: %i' % (at))
        if self.line and self.line_time == 0:
            #we've been waiting for our first open
            self.line_time = at
        if self.line_time < at:
            self.new_line()
            self._ecdh(line_id, sender_ecc)
            return
        if self.line.is_complete:
            #remote didn't get our response open
            self._send_open()
        else:
            self._ecdh(line_id, sender_ecc)

    def open_channel(self, ctype, initial_data=None, timeout=10):
        ch = Channel(self, ctype)
        self.channels[ch.c] = ch
        ch.start()
        if initial_data is not None:
            d, b = initial_data
            d['type'] = ctype
            ch.send(d, b)
        #TODO: "wait for first response" logic is all over the place
        return ch
