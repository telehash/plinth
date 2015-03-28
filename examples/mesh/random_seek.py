#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
TeleHash test script that connects to a seed and seeks a random hashname
"""

import os
import os.path
import logging
import argparse
import time

try:
    import simplejson as json
except ImportError:
    import json

import plinth

log = plinth.log


def seek_rand(keyfile, seedfile):
    try:
        with open(keyfile, 'r') as f:
            app_id = f.read()
        log.debug('Read private key from %s' % keyfile)
    except Exception, err:
        log.debug('Exception: %s' % err.message)
        app_id = plinth.Switch.new_key()
        umask = os.umask(0177)
        with open(keyfile, 'w') as f:
            f.write(app_id)
        os.umask(umask)
        log.debug('Saved new key in %s' % keyfile)
    try:
        with open(seedfile, 'r') as f:
            seed_list = json.loads(f.read())
    except Exception, msg:
        print('Unable to read initial seed list:')
        print(msg)
        return

    switch = plinth.Switch(key=app_id, seeds=seed_list)
    random_seek = os.urandom(32).encode('hex')
    log.warn("Seeking: %s" % random_seek)
    switch.start()
    switch.ping(random_seek)
    for x in range(10):
        time.sleep(1)
        random_seek = os.urandom(32).encode('hex')
        log.warn("Seeking: %s" % random_seek)
        switch.ping(random_seek)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--keyfile',
                        help='Location of private key',
                        default='~/.plinth/test_id')
    parser.add_argument('-s', '--seedfile',
                        help='Location of seed list',
                        default='~/.plinth/seeds.json')
    parser.add_argument('-v', dest='verbose', action='store_true')
    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    log.addHandler(logging.StreamHandler())
    keyfile = os.path.expanduser(args.keyfile)
    seedfile = os.path.expanduser(args.seedfile)
    seek_rand(keyfile=keyfile, seedfile=seedfile)
