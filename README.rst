"Quickstart"
------------

A better place to start might be http://telehash.org

This will break. You were warned. :)

If you aren't already using virtualenvs, it is highly recommended for
playing with plinth: http://virtualenvwrapper.readthedocs.org/

You will also need libevent (for gevent) which should be easily found in
most Linux distributions, or installed on Mac OS X from http://brew.sh/

Next you'll want to `mkdir $HOME/.plinth` and put in a seeds.json which
you can find at: https://github.com/telehash/thjs/blob/master/seeds.json

Now, from within your virtualenv:

| $ pip install plinth
| $ examples/seed.py -v

Now behold as your terminal fills with indecipherable debug details.
