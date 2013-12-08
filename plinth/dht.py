# -*- coding: utf-8 -*-

from bitarray import bitarray, bitdiff

from . import packet

class DHT(object):
    def __init__(self, root, seeds):
        self.root = root
        self.seeds = seeds
        self.lines = {}

    def start(self):
        for seed in self.seeds:
            #Open a line, then .seek yourself. That's it, I think.
            pass

class Line(object):
    def __init__(self):
        pass
