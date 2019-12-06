# https://github.com/pfalcon/micropython-lib/blob/master/uuid/uuid.py

import os
import ubinascii


class UUID:
    def __init__(self, bytes):
        if len(bytes) != 16:
            raise ValueError('bytes arg must be 16 bytes long')
        self.bytes = bytes

    @property
    def hex(self):
        return ubinascii.hexlify(self.bytes).decode()

    def pure_str(self):
        h = self.hex
        return h

    def __str__(self):
        h = self.hex
        return '-'.join((h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]))

    def __repr__(self):
        return "<UUID: %s>" % str(self)



def uuid4():
    """Generates a random UUID compliant to RFC 4122 pg.14"""
    random = bytearray(os.urandom(16))
    random[6] = (random[6] & 0x0F) | 0x40
    random[8] = (random[8] & 0x3F) | 0x80
    return UUID(bytes=random)
