# -*- coding: utf-8 -*-

from .log import log
from .identity import SwitchID


class DHT(object):
    """Manages information about remote Switches and Lines"""
    def __init__(self, local, lines, switches):
        self.kbucket = []
        self.local = local
        self.lines = lines
        self.switches = switches

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
        bkt = self.local.kdist(switch_id)
        log.debug("%s in bucket: %s" % (hn, bkt))
        if hn == self.local.hash_name:
            pass
        elif hn in self.switches:
            ip, port = self.switches[hn].address
            see = ','.join((hn, ip, str(port)))
            see_list.append(see)
        return see_list
