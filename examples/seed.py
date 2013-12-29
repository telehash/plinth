#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
A sample TeleHash seed that listens and introduces.
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


def run_seed(keyfile, seedfile, port):
    try:
        with open(keyfile, 'r') as f:
            id_key = f.read()
        log.debug('Read private key from %s' % keyfile)
    except:
        id_key = plinth.SwitchID().priv_key
        umask = os.umask(0177)
        with open(keyfile, 'w') as f:
            f.write(id_key)
        os.umask(umask)
        log.debug('Saved new key in %s' % keyfile)
    try:
        with open(seedfile, 'r') as f:
            seed_list = json.loads(f.read())
    except Exception, msg:
        log.warn('Unable to read initial seed list:')
        log.warn(msg)
        seed_list = []
        pass

    seed = plinth.Switch(listener=port, key=id_key, seeds=seed_list)
    seed.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--keyfile',
                        help='Location of private key',
                        default='~/.plinth/seed_id')
    parser.add_argument('-s', '--seedfile',
                        help='Location of seed list',
                        default='~/.plinth/seeds.json')
    parser.add_argument('-p', '--port', type=int,
                        help='UDP Port to listen on',
                        default=42424)
    parser.add_argument('-v', dest='verbose', action='store_true')
    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    log.addHandler(logging.StreamHandler())
    keyfile = os.path.expanduser(args.keyfile)
    seedfile = os.path.expanduser(args.seedfile)
    run_seed(keyfile=keyfile, seedfile=seedfile, port=args.port)
