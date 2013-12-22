# -*- coding: utf-8 -*-

import os

import gevent
from gevent.server import DatagramServer
from tomcrypt import ecc
from tomcrypt.hash import sha256
from tomcrypt.cipher import aes

from .log import log
from .identity import SwitchID
from .packet import Packet
from .line import Line
from .channel import Channel


class Switch(DatagramServer):
    """An application's TeleHash Switch instance.

    Used to communicate securely with other applications over the TeleHash
    mesh network.
    """
    def __init__(self, listener=0, key=None, ephemeral=False, seeds=None):
        super(Switch, self).__init__(listener)
        self.switches = {}
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
            self.switches[seed_id.hash_name] = remote
            address = (seed['ip'], seed['port'])
            remote.new_line(address)
            self.ping(seed_id.hash_name)

    def handle(self, data, address):
        log.debug('Received %i bytes from %s' % (len(data), address[0]))
        if len(data) <= 4:
            #Empty / NAT-punching packets can be ignored
            return
        try:
            p = Packet(data)
            if p.open:
                sender_ecc = self.id.decrypt(p.open)
                sender = p.read_open(self.id.hash_name, sender_ecc)
                remote = self.switches.get(sender.hash_name)
                if remote is None:
                    """
                    This is *our view* of the remote switch, but it still
                    needs to be rethought.  The RemoteSwitch() object
                    to be able to sign & decrypt opens, and update the
                    local Switch instance with Line status changes.
                    Some of this can probably be refactored to use some
                    of gevent's specialized structures.
                    """
                    remote = RemoteSwitch(self, sender)
                    self.switches[sender.hash_name] = remote
                remote.handle_open(p, address)
            elif p.line in self.lines:
                #TODO: turn this into a queue
                #TODO: also rename it, because it's the remote switch
                #TODO: container rather than the direct line object
                self.lines[p.line].recv(p, address)
            #Packet dropped otherwise
        except Exception, err:
            log.debug('Invalid Packet: %s' % err)

    def open_channel(self, hash_name, ctype, initial_data=None):
        remote = self.switches.get(hash_name)
        if remote is None:
            switch_id = SwitchID(hash_name=hash_name)
            remote = RemoteSwitch(self, switch_id)
            self.switches[hash_name] = remote
        return remote.open_channel(ctype, initial_data)

    def ping(self, hash_name):
        return self.open_channel(hash_name, 'seek', self.id.hash_name)


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
        #safe to remove this; keep _ecc_pub for open retransmits
        del self._ecc
        self.line.complete(remote_line, secret)

    def new_line(self, address):
        """Creates or replaces a secure line to the remote switch

        TODO: Look into gevent.event to detect response opens
        """
        self.address = address
        if self.line:
            log.debug('Invalidating previous line: %s' % self.line.id)
            #unregister Line from Switch
            del self.local.lines[self.line.id]
            del self.line
        self.line = Line()
        self.local.lines[self.line.id] = self
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
            self.local.id.pub_key_der)
        self._send_open()
        retried = 0
        gevent.sleep(1)
        while not self.line.is_complete and retried < 2:
            self._send_open()
            retried += 1
            log.debug('open retry %i' % retried)
            gevent.sleep(1)

    def send(self, data, timeout=5):
        """Take a Channel packet, wrap it in a line, and send

        TODO: implement timeout to wait for line
        """
        if not self.line:
            log.debug('Time to implement seek already.')
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
        """Transmit packet on best network path

        TODO: Implement multi-homing
        """
        log.debug('Sending %s to %s' % (len(data), self.address))
        self.local.sendto(data, self.address)

    def recv(self, p, address):
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
            ch = Channel.incoming(self.send, c, t, data, body)
            self.channels[c] = ch
        else:
            candidate.recv(data, body)

    def _send_open(self):
        iv = os.urandom(16)
        aes_key = sha256(self._ecc_pub)
        enc_body = aes(aes_key.digest(), iv).encrypt(self._open)
        aes_key.update(self.line.id.decode('hex'))
        sig = self.local.id.sign(sha256(enc_body).digest())
        enc_sig = aes(aes_key.digest(), iv).encrypt(sig)
        o = self.id.encrypt(self._ecc_pub)
        data = Packet.wrap_open(o, iv, enc_sig, enc_body)
        self._send(data)
        log.debug('Open to: %s' % self.id.hash_name)
        log.debug('Line: %s to %s' % (self.line.id, self.line.rid))

    def handle_open(self, p, address):
        """Deal with incoming open from this remote switch

        TODO: probably need to add a lock here
        """
        log.debug('Open from: %s' % self.id.hash_name)
        log.debug('Line: %s from %s' % (self.line.id, self.line.rid))
        log.debug('At: %i' % (p.at))
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

    def open_channel(self, ctype, initial_data):
        ch = Channel(self.send, None, ctype)
        self.channels[ch.c] = ch
        ch.send(initial_data)
