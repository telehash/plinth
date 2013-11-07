plinth
======

Python Library for InterNetworking with TeleHash

Early work in progress. Sends a "seek" for a random hashname after opening a line with a specified seed.

Quickstart
----------

Prerequisite: http://virtualenvwrapper.readthedocs.org/en/latest/

````
$ mkvirtualenv plinth
(plinth)$ pip install -r requirements.txt
````

Create a local_vars.py and define your seed:

````
DEST_KEY = "-----BEGIN PUBLIC KEY----- ..."
DEST_HASH = "168c4b41..."
DEST_HOST = "192.168.1.42"
DEST_PORT = 42424
````

And you should receive a "see" response:
````
$ workon plinth
(plinth)$ python crypto.py
````
