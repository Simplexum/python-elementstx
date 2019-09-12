# Copyright (C) 2019 The python-elementstx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""Blech32 encoding and decoding"""

from elementstx.liquid_addr import encode, decode
import bitcointx
import bitcointx.core


class Blech32Error(bitcointx.core.AddressDataEncodingError):
    pass


class Blech32ChecksumError(Blech32Error):
    pass


class CBlech32Data(bytes):
    """Blech32-encoded data

    Includes a witver and checksum.
    """
    blech32_hrp = None

    def __new__(cls, s):
        """from blech32 addr to """
        if cls.blech32_hrp is None:
            raise TypeError(
                'CBlech32Data subclasses should define blech32_hrp attribute')
        witver, data = decode(cls.blech32_hrp, s)
        if witver is None and data is None:
            raise Blech32Error('Blech32 decoding error')

        return cls.from_bytes(data, witver=witver)

    def __init__(self, s):
        """Initialize from blech32-encoded string

        Note: subclasses put your initialization routines here, but ignore the
        argument - that's handled by __new__(), and .from_bytes() will call
        __init__() with None in place of the string.
        """

    @classmethod
    def from_bytes(cls, witprog, witver=None):
        """Instantiate from witver and data"""
        if witver is None or not (0 <= witver <= 16):
            raise ValueError(
                'witver must be in range 0 to 16 inclusive; got %r' % witver)
        self = bytes.__new__(cls, witprog)
        self.witver = witver

        return self

    def to_bytes(self):
        """Convert to bytes instance

        Note that it's the data represented that is converted; the checkum and
        witver is not included.
        """
        return b'' + self

    def __str__(self):
        """Convert to string"""
        return encode(self.__class__.blech32_hrp, self.witver, self)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, str(self))


__all__ = (
    'Blech32Error',
    'Blech32ChecksumError',
    'CBlech32Data',
)
