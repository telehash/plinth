plinth
======

Python Library for InterNetworking with TeleHash

Early work in progress. Sends a "seek" for a random hashname after opening a line with a specified seed.

Quickstart
----------

Prerequisite: http://virtualenvwrapper.readthedocs.org/en/latest/

$ mkvirtualenv plinth
$ pip install -r requirements.txt

Create a local_vars.py and define your seed:

DEST_KEY =
DEST_HASH =
DEST_HOST =
DEST_PORT =

$ python crypto.py

