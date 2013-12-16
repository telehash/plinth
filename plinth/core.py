# -*- coding: utf-8 -*-

import os

import gevent
from gevent.server import DatagramServer
from tomcrypt import ecc
from tomcrypt.hash import sha256
from tomcrypt.cipher import aes

from .log import log
from .packet import Packet
from .dht import DHT
from .identity import SwitchID
from .line import Line


class Switch(DatagramServer):
    """An application's TeleHash Switch instance.

    Used to communicate securely with other applications over the TeleHash
    mesh network.
    """
    def __init__(self, listener=0, key=None, ephemeral=False, seeds=None):
        super(Switch, self).__init__(listener)
        self.active = {}
        self.lines = {}
        if key is None:
            if not ephemeral:
                raise ValueError("No identity key specified")
            else:
                self.id = SwitchID()
        if isinstance(key, (str, unicode)):
            self.id = SwitchID(key=key)
            if not self.id.is_private:
                raise ValueError("Need private key for local identity")
        else:
            raise ValueError("Private key must be in PEM format.")
        self.seeds = seeds

    def start(self):
        log.debug('My public key:\n%s' % self.id.pub_key)
        log.debug('My hash name: %s' % self.id.hash_name)
        log.debug('Listening for open packets on port %i' % self.address[1])
        super(Switch, self).start()
        for seed in self.seeds:
            seed_id = SwitchID(hash_name=seed['hashname'],
                               key=seed['pubkey'])
            remote = RemoteSwitch(self, seed_id)
            self.active[seed_id.hash_name] = remote
            address = (seed['ip'], seed['port'])
            log.debug('connecting to seed at %s' % str(address))
            remote.new_line(address)

    def handle(self, data, address):
        log.debug('Received %i bytes from %s' % (len(data), address[0]))
        if len(data) == 4:
            #Empty ping packets can be ignored
            return
        try:
            p = Packet(data)
            if p.open:
                sender_ecc = self.id.decrypt(p.open)
                sender = p.read_open(self.id.hash_name, sender_ecc)
                remote = self.active.get(sender.hash_name)
                if remote is None:
                    #This is *our view* of the remote switch
                    remote = RemoteSwitch(self, sender)
                    self.active[sender.hash_name] = remote
                remote.handle_open(p, address)
            elif p.line in self.lines:
                #TODO: turn this into a queue
                self.lines[p.line].recv(p, address)
            #Packet dropped otherwise
        except Exception, err:
            log.debug('Invalid Packet: %s' % err)

    def open_channel(self, remote, ctype):
        ch = Channel(remote, ctype)

    def ping(self, remote):
        return self.open_channel(remote, 'ping')


class RemoteSwitch(object):
    def __init__(self, local, switch_id):
        self.id = switch_id
        self.local = local
        self.line = False
        self.line_time = 0
        self.channels = {}
        self.address = None

    def _ecdh(self, remote_line, remote_ecc):
        secret = self._ecc.shared_secret(ecc.Key(remote_ecc))
        log.debug('ECDH: %s' % secret.encode('hex'))
        del self._ecc
        self.line.complete(remote_line, secret)

    def new_line(self, address):
        self.address = address
        if self.line:
            del self.local.lines[self.line.id]
        self.line = Line()
        self.local.lines[self.line.id] = self
        self._ecc = ecc.Key(256)
        self._ecc_pub = self. \
            _ecc.public.as_string(format='der', ansi=True)
        self._open = Packet.create_open(
            self.id.hash_name,
            self.line.id,
            self.local.id.pub_key_der)
        #TODO: add retransmit when initiating (but where?)
        self._send_open()

    def send(self, data):
        """Transmit packet on best network path

        TODO: Implement multi-homing
        """
        self.local.sendto(data, self.address)

    def recv(self, p, address):
        self.line.recv(p.iv, p.payload)

    def _send_open(self):
        aes_key = sha256(self._ecc_pub)
        iv = os.urandom(16)
        enc_body = aes(aes_key.digest(), iv).encrypt(self._open)
        sig = self.local.id.sign(sha256(enc_body).digest())
        aes_key.update(self.line.id.decode('hex'))
        enc_sig = aes(aes_key.digest(), iv).encrypt(sig)
        o = self.id.encrypt(self._ecc_pub)
        outbound = Packet.wrap_open(o, iv, enc_sig, enc_body)
        log.debug('Sending open to: %s' % self.id.hash_name)
        self.send(outbound)

    def handle_open(self, p, address):
        """Deal with incoming open from this remote switch

        TODO: probably need to add a lock here
        """
        if self.line and self.line_time == 0:
            #we've been waiting for our first open
            self.line_time = p.at
        if self.line_time < p.at:
            self.new_line(address)
        if self.line.is_complete:
            #remote didn't get our response open
            self._send_open()
        else:
            self._ecdh(p.line, p.ecc)
