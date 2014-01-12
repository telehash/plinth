# -*- coding: utf-8 -*-

from .log import log
from .identity import SwitchID
from .remote import RemoteSwitch


class DHT(object):
    """Manages information about remote Switches and Lines"""
    def __init__(self, local_id, transmit):
        self.me = local_id
        self.transmit = transmit
        self.kbucket = []
        self.linemap = {}
        self.active = {}

    def maintain(self):
        """DHT Maintenance

        initial TODO:
        put active lines into kbuckets
        remove inactive lines from kbuckets
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
        remote.handle_open(p, address)

    def handle_line(self, p, address):
        remote = self.linemap.get(p.line)
        if remote is not None:
            remote.recv(p, address)
        else:
            log.debug('unrecognized line: %s' % p.line)

    def connect(self, switch_id, paths):
        if switch_id.hash_name in self.active:
            log.debug('connect for known hash')
        else:
            log.debug('connect for unknown hash')
        remote = self.register(switch_id, paths)
        #apparently not always redundant
        remote.path_hint(paths)
        remote.start()

    def open_channel(self, hash_name, ctype, initial_data=None):
        log.debug('opening {} channel to: {}'.format(ctype, hash_name))
        switch_id = SwitchID(hash_name)
        remote = self.register(switch_id)
        return remote.open_channel(ctype, initial_data)
