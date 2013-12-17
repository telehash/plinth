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
