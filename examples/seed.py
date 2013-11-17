#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
A sample TeleHash seed that listens and introduces.
"""

import os
import os.path
import logging
import argparse

import plinth

log = plinth.log


def run_seed(keyfile, port):
    try:
        id_key = open(keyfile).read()
        seed_id = plinth.HashName(id_key)
        log.debug('Read private key from %s' % keyfile)
    except:
        seed_id = plinth.HashName()
        umask = os.umask(0177)
        with open(keyfile, 'w') as f:
            f.write(seed_id.key.as_string())
        os.umask(umask)
        log.debug('Saved new key in %s' % keyfile)

    seed = plinth.Switch(seed_id)
    seed.start(listen=port)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--keyfile',
                        help='Location of private key',
                        default='~/.plinth/seed_id')
    parser.add_argument('-p', '--port', type=int,
                        help='UDP Port to listen on',
                        default=42424)
    parser.add_argument('-v', dest='verbose', action='store_true')
    args = parser.parse_args()
    if args.verbose is True:
        log.setLevel(logging.DEBUG)
    log.addHandler(logging.StreamHandler())
    keyfile = os.path.expanduser(args.keyfile)
    run_seed(keyfile=keyfile, port=args.port)
