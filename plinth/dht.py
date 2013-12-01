# -*- coding: utf-8 -*-

from bitarray import bitarray, bitdiff

from . import packet

class DHT(object):
    def __init__(self, root):
        self.root = root
        self.lines = {}

    @staticmethod
    def distance(a, b):
        a_ = bitarray()
        b_ = bitarray()
        a_.frombytes(a)
        b_.frombytes(b)
        return bitdiff(a_, b_)

class Line(object):
    def __init__(self):
        pass
