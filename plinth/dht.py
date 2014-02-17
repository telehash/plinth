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
        for remote in self.active.values():
            gevent.spawn(self.send_seek, remote, self.me.hash_name)
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

    def handle_open(self, switch_id, sender_ecc, line_id, at, address):
        remote = self.register(switch_id)
        remote.openq.put((sender_ecc, line_id, at, address))

    def handle_line(self, wrapper, payload, address):
        remote = self.linemap.get(wrapper['line'])
        if remote is not None:
            remote.packetq.put((wrapper, payload, address))
        else:
            log.debug('unrecognized line: %s' % wrapper['line'])

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
        self._open_channel(remote, 'seek', (seek,''))

    def send_peer(self, remote, hn):
        pass

    def channel_handler(self, remote, ch, data, body):
        log.debug('DHT recv: {}'.format(ch.t))
        if ch.t == 'seek':
            hn = data['seek']
            log.debug('Remote seeking: {}'.format(hn))
            see_list = self.seek(hn)
            resp = {'end': True, 'see': see_list}
            ch.send(resp)
            return
        elif ch.t == 'peer':
            #TODO: Check for desire to be discoverable first
            hn = data.get('peer')
            #TODO: Distinguish between "seen hashname" and "active line"
            if hn in self.active:
                switch_id = SwitchID(hn)
                peer_to = self.register(switch_id)
                self.send_connect(peer_to, remote)
            return
        if ch.t == 'connect':
            paths = data.get('paths', [])
            connect_id = SwitchID(key=body)
            self.connect(connect_id, paths)
            return

    def send_connect(self, peer_to, remote):
        paths = peer_to.all_paths()
        if len(paths) > 0:
            connect = ({'paths': paths}, remote.id.pub_key_der)
            self._open_channel(peer_to, 'connect', connect)

    def connect(self, switch_id, paths):
        #attempting to debug rogue connects
        hn = switch_id.hash_name
        alert = False
        if hn in self.active:
            alert = True
        else:
            log.debug('connecting to: {}'.format(hn))
        remote = self.register(switch_id, paths)
        if alert:
            log.debug('connect for known: {}'.format(hn))
            if remote.line:
                log.debug('line in progress: {} to {}'
                    .format(remote.line.rid, remote.line.id))
                log.debug('line time:'.format(remote.line_time))
            else:
                #stopgap
                log.debug('attempting to force connect')
                gevent.spawn_later(1, self.send_seek, remote, self.me.hash_name)

    def _open_channel(self, remote, ctype, initial_data=None):
        log.debug('opening {} channel to: {}'
            .format(ctype, remote.id.hash_name))
        return remote.open_channel(ctype, initial_data)

    def open_channel(self, hash_name, ctype, initial_data=None):
        switch_id = SwitchID(hash_name)
        remote = self.register(switch_id)
        return self._open_channel(remote, ctype, initial_data)
