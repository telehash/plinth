#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
A sample telehash router that listens and introduces.
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


def start_router(idfile, linkfile, port):
    try:
        with open(idfile, 'r') as f:
            identity = f.read()
        log.debug('Read local identity from %s' % idfile)
    except:
        identity = plinth.e3x.generate()
        umask = os.umask(0177)
        with open(idfile, 'w') as f:
            f.write(identity)
        os.umask(umask)
        log.debug('Saved local identity in %s' % idfile)
    try:
        with open(linkfile, 'r') as f:
            link_list = json.loads(f.read())
    except Exception, msg:
        log.warn('Unable to read initial link list:')
        log.warn(msg)
        link_list = []
        pass

    router = plinth.Switch(listener=port, key=id_key, links=link_list)
    router.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--idfile',
                        help='Location of private key(s)',
                        default='~/.plinth/router_id.json')
    parser.add_argument('-l', '--linkfile',
                        help='Location of known links file',
                        default='~/.plinth/links.json')
    parser.add_argument('-p', '--port', type=int,
                        help='UDP Port to listen on',
                        default=42424)
    parser.add_argument('-v', dest='verbose', action='store_true')
    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    log.addHandler(logging.StreamHandler())
    idfile = os.path.expanduser(args.idfile)
    linkfile = os.path.expanduser(args.linkfile)
    start_router(idfile=idfile, linkfile=linkfile, port=args.port)
