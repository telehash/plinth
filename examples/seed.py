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
        log.debug('Reading from %s' % keyfile)
        id_key = open(keyfile).read()
    except:
        log.debug('Unable to load from %s' % keyfile)
        id_key = None

    seed = plinth.Switch(key=id_key)
    if id_key == None:
        log.debug('Saving new private key')
        umask = os.umask(0177)
        with open(keyfile, 'w') as f:
            f.write(seed.priv_key.as_string())
        os.umask(umask)
    seed.run(port=port)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--keyfile',
                        help='Location of private key', 
                        default='~/.seed_id')
    parser.add_argument('-p', '--port', type=int,
                        help='UDP Port to listen on', 
                        default=42424)
    parser.add_argument('-v', dest='verbose', action='store_true')
    args = parser.parse_args()
    if args.verbose == True:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
    log.addHandler(logging.StreamHandler())
    run_seed(keyfile=os.path.expanduser(args.keyfile), port=args.port)
    
