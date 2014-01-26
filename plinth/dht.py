# -*- coding: utf-8 -*-

import gevent
from gevent.queue import Queue

from .log import log
from .identity import SwitchID
from .remote import RemoteSwitch


class DHT(gevent.Greenlet):
    """Manages information about remote Switches and Lines"""

    k = 8
    concurrency = 3
    kbucket = []
    linemap = {}
    active = {}

    def __init__(self, local_id, transmit):
        self.me = local_id
        self.transmit = transmit
        super(DHT, self).__init__()

    def _run(self):
        self.running = True
        for r in self.active:
            gevent.spawn(self.send_seek, r, self.me.hash_name)
        while self.running:
            self.maintain()
            gevent.sleep(30)

    def maintain(self):
        """DHT Maintenance

        initial TODO:
        put active lines into kbuckets
        remove inactive lines from kbuckets (why bother?)
        remove remaining excess lines from kbuckets
        ping near-expired lines still in kbuckets
        signal unbucketed lines to check for active user channels?
        expire old switches?
        """
        pass

    def seek(self, hn):
        see_list = []
        switch_id = SwitchID(hn)
        bkt = self.me.kdist(switch_id)
        log.debug("%s in bucket: %s" % (hn, bkt))
        if hn == self.me.hash_name:
            pass
        elif hn in self.active:
            remote = self.active.get(hn)
            if remote.best_path() is not None:
                ip, port = remote.best_path()
                see = ','.join((hn, ip, str(port)))
                see_list.append(see)
        return see_list

    def register(self, switch_id, paths=[]):
        remote = self.active.get(switch_id.hash_name)
        if remote is None:
            remote = RemoteSwitch(switch_id, self)
            self.active[switch_id.hash_name] = remote
            remote.path_hint(paths)
            remote.start()
        elif switch_id.known:
            remote.id.found_key(switch_id.pub_key_der)
        return remote

    def handle_open(self, switch_id, p, address):
        remote = self.register(switch_id)
        remote.openq.put((p, address))

    def handle_line(self, p, address):
        remote = self.linemap.get(p.line)
        if remote is not None:
            remote.packetq.put((p, address))
        else:
            log.debug('unrecognized line: %s' % p.line)

    def locate(self, hn):
        """
        while not found
        seek hashname at <concurrency> peers
        try again
        """
        pass

    def send_seek(self, remote, hn):
        """
        create seek channel
        wait for see, and update DHT
        """
        seek = {'seek': hn}
        self.open_channel(remote, 'seek', seek)

    def send_peer(self, remote, hn):
        pass

    def channel_handler(self, ch, data, body):
        log.debug('DHT recv: {}'.format(ch.t))
        if ch.t == 'seek':
            hn = data['seek']
            log.debug('Remote seeking: {}'.format(hn))
            see_list = self.seek(hn)
            resp = {'end': True, 'see': see_list}
            ch._send(resp)
            return
        elif ch.t == 'peer':
            #TODO: Check for desire to be discoverable first
            #TODO: Send connect
            resp = {'end': True, 'err': 'unimplemented'}
            ch._send(resp)
            return
        if ch.t == 'connect':
            paths = data.get('paths', [])
            connect_id = SwitchID(key=body)
            self.connect(connect_id, paths)
            return

    def connect(self, switch_id, paths):
        if switch_id.hash_name in self.active:
            log.debug('connect for known: {}'.format(switch_id.hash_name))
        else:
            log.debug('connecting to: {}'.format(switch_id.hash_name))
        remote = self.register(switch_id, paths)

    def open_channel(self, hash_name, ctype, initial_data=None):
        log.debug('opening {} channel to: {}'.format(ctype, hash_name))
        switch_id = SwitchID(hash_name)
        remote = self.register(switch_id)
        return remote.open_channel(ctype, initial_data)
