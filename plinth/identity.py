# -*- coding: utf-8 -*-

from tomcrypt import rsa
from tomcrypt.hash import sha256

from .log import log


class SwitchID(object):
    """Container for key & hashname of local or remote Switch

    After an absurd amount of internal debate, I'm storing hash names as
    Python integers internally. We'll see how that goes.
    """
    key = None

    def __init__(self, hash_name=None, key=None):

        if isinstance(key, (str, unicode)):
            self.key = rsa.Key(key)

        #This should only ever be the local Switch.
        if hash_name is None:
            if key is None:
                #Fashion a new Switch from the Platonic Realm
                self.key = rsa.Key(2048)
            self._hash = self._hash_from_key(self.key)
        else:
            self._validate_hash_name(hash_name)
            self._hash = self._hash_from_string(hash_name)

    @staticmethod
    def _validate_hash_name(hn):
        if isinstance(hn, (str, unicode)) and len(hn) == 64:
            try:
                hexval = int(hn, 16)
                return True
            except:
                raise ValueError("Not a HashName.")
        raise ValueError("Not a HashName.")

    @staticmethod
    def _hash_from_key(key):
        pub_der = key.public.as_string(format='der')
        hex_string = sha256(pub_der).hexdigest()
        #TODO: Apparently this is what @classmethod is for?
        return SwitchID._hash_from_string(hex_string)

    @staticmethod
    def _hash_from_string(hash_name):
        return int(hash_name, 16)

    @property
    def hash_name(self):
        """Converts from internal int storage to canonical hexstring"""
        return format(self._hash, '064x')

    @staticmethod
    def _kdist(a, b):
        """Returns the Kademlia distance from another SwitchID

        Most of the literature phrases this poorly, but the metric (or
        possibly pseudometric, depending on whether you want to speak
        with topologists) we care about is something closer to "greatest
        common subnet mask" for the network engineers.

        Since there isn't any fantastic way to talk about this that makes
        sense unambiguously to the math guys and the bit twiddlers, what
        this function returns for now is the index of the first significant
        bit the remote SwitchID doesn't share in common with us.

        This entire essay was written prior to refactoring everything into
        internal integer storage. Clearly the refactor was astute.
        """

        return 256 - (a ^ b).bit_length()

    def kdist(self, other):
        return self._kdist(self._hash, other._hash)

    @property
    def known(self):
        if self.key is not None:
            return True
        return False

    @property
    def priv_key(self):
        if self.key is None or self.key.is_public:
            return None
        else:
            return self.key.as_string(type='private')

    @property
    def pub_key(self):
        if self.key is None:
            return None
        else:
            return self.key.public.as_string()

    @property
    def pub_key_der(self):
        if self.key is None:
            return None
        else:
            return self.key.public.as_string(format='der')

    @property
    def is_private(self):
        if self.key is None:
            return False
        else:
            return self.key.is_private

    def found_key(self, key):
        """Validates / updates learned pub_key after .seek"""
        candidate = rsa.Key(key)
        if self.key is not None:
            if self.key.as_dict() == candidate.as_dict():
                #We must've already found it. Thanks anyway!
                return True
            else:
                #TODO: define a class of Security Exceptions
                raise ValueError("Someone is lying to you, hoss")
        candidate_hash = self._hash_from_key(candidate)
        if self.hash_name == candidate_hash:
            self.key = candidate
            return True
        else:
            """
            If a rogue Switch sends a .connect to us with a spoofed public
            key, we'll probably end up here. Just ignore that?
            """
            return False

    def encrypt(self, payload):
        return self.key.encrypt(payload).encode('base64').translate(None, '\n')

    def decrypt(self, payload):
        try:
            return self.key.decrypt(payload.decode('base64'))
        except Exception, err:
            raise Exception("Probably not our hashname: %s" % err)

    def sign(self, payload):
        return self.key.sign(payload, padding='v1.5', hash='sha256')

    def verify(self, payload, sig):
        return self.key.verify(payload, sig, padding='v1.5', hash='sha256')
