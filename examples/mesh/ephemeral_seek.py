#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
TeleHash test script that connects to a seed and seeks a random hashname

This version doesn't save a generated private key. After receiving a seek
response, it vanishes like tears in the rain. Certain to clog up buggy
switches with phantom hashnames that will never rejoin the mesh.
"""

import os
import os.path
import logging
import argparse

try:
    import simplejson as json
except ImportError:
    import json

import plinth

log = plinth.log


def seek_rand_eph(seedfile):
    try:
        with open(seedfile, 'r') as f:
            seed_list = json.loads(f.read())
    except Exception, msg:
        print('Unable to read initial seed list:')
        print(msg)
        return

    switch = plinth.Switch(ephemeral=True, seeds=seed_list)
    random_seek = os.urandom(32).encode('hex')
    log.warn("Seeking: %s" % random_seek)
    switch.start()
    switch.ping(random_seek)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--seedfile',
                        help='Location of seed list',
                        default='~/.plinth/seeds.json')
    parser.add_argument('-v', dest='verbose', action='store_true')
    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    log.addHandler(logging.StreamHandler())
    seedfile = os.path.expanduser(args.seedfile)
    seek_rand_eph(seedfile=seedfile)
