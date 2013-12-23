# -*- coding: utf-8 -*-

"""
Big Bucket o' Exceptions
"""


class PacketException(ValueError):
    """There was an error encoding or decoding your packet."""


class ChannelException(ValueError):
    """Channel woes"""
