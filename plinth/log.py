# -*- coding: utf-8 -*-

import logging

try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

log = logging.getLogger(__name__)
logging.getLogger(__name__).addHandler(NullHandler())
