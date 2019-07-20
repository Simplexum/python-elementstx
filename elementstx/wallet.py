# Copyright (C) 2019 The python-elementstx developers
#
# This file is part of python-elementstx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-elementstx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501

from bitcointx.core.key import (
    CPubKey
)
from bitcointx.wallet import (
    WalletCoinClassDispatcher, WalletCoinClass,
    CCoinAddress, P2SHCoinAddress, P2WSHCoinAddress,
    P2PKHCoinAddress, P2WPKHCoinAddress,
    CBase58CoinAddress, CBech32CoinAddress,
    CCoinAddressError,
    CCoinKey, CCoinExtKey, CCoinExtPubKey
)
from bitcointx.util import dispatcher_mapped_list
from .core import CoreElementsClassDispatcher


class WalletElementsClassDispatcher(WalletCoinClassDispatcher,
                                    depends=[CoreElementsClassDispatcher]):
    ...


class WalletElementsClass(WalletCoinClass,
                          metaclass=WalletElementsClassDispatcher):
    ...


class CConfidentialAddressError(CCoinAddressError):
    """Raised when an invalid confidential address is encountered"""


class CCoinConfidentialAddress(CCoinAddress, WalletElementsClass):
    @classmethod
    def from_unconfidential(cls, unconfidential_adr, blinding_pubkey):
        """Convert unconfidential address to confidential

        Raises CConfidentialAddressError if blinding_pubkey is invalid
        (CConfidentialAddressError is a subclass of CCoinAddressError)

        unconfidential_adr can be string or CBase58CoinAddress
        instance. blinding_pubkey must be a bytes instance
        """
        if not isinstance(blinding_pubkey, (bytes, bytearray)):
            raise TypeError(
                'blinding_pubkey must be bytes or bytearray instance; got %r'
                % blinding_pubkey.__class__)
        if not isinstance(blinding_pubkey, CPubKey):
            blinding_pubkey = CPubKey(blinding_pubkey)
        if not blinding_pubkey.is_fullyvalid():
            raise CConfidentialAddressError('invalid blinding pubkey')

        if not isinstance(unconfidential_adr, CBase58CoinAddress):
            raise CConfidentialAddressError(
                'non-base58 confidential addresses are not supported for now')

        def recursive_search(candidate):
            b58pfx = getattr(candidate, 'base58_prefix', None)
            if b58pfx and len(b58pfx) > 1 and \
                    unconfidential_adr.base58_prefix == b58pfx[1:]:
                return candidate.from_bytes(blinding_pubkey + unconfidential_adr)

            for next_candidate in dispatcher_mapped_list(candidate):
                result = recursive_search(next_candidate)
                if result is not None:
                    return result
            return None

        result = recursive_search(cls)
        if result is not None:
            return result

        raise CConfidentialAddressError(
            'cannot create {} from {}: cannot find matching confidential address class'
            .format(cls, unconfidential_adr.__class__.__name__))

    def to_unconfidential(self):
        return self._unconfidential_address_class.from_bytes(self[33:])

    @property
    def blinding_pubkey(self):
        return CPubKey(self[0:33])

    def to_scriptPubKey(self):
        return self.to_unconfidential().to_scriptPubKey()

    def to_redeemScript(self):
        return self.to_unconfidential().to_scriptPubKey()

    def from_scriptPubKey(self):
        raise CCoinAddressError(
            'cannot create confidential address from scriptPubKey')


class CBase58CoinConfidentialAddress(CCoinConfidentialAddress, CBase58CoinAddress):
    ...


# class CBlech32ConfidentialAddress(CCoinConfidentialAddress, WalletElementsClass):


class P2SHCoinConfidentialAddress(CBase58CoinConfidentialAddress,
                                  next_dispatch_final=True):
    ...


class P2PKHCoinConfidentialAddress(CBase58CoinConfidentialAddress,
                                   next_dispatch_final=True):
    ...


# class P2WSHConfidentialAddress(P2WSHCoinAddress, CBlech32ConfidentialAddress):
# class P2WPKHConfidentialAddress(P2PKHCoinAddress, CBlech32ConfidentialAddress):

class CElementsAddress(CCoinAddress, WalletElementsClass):
    ...


class CElementsConfidentialAddress(CCoinConfidentialAddress, CElementsAddress):
    ...


class CBase58ElementsAddress(CBase58CoinAddress, CElementsAddress):
    ...


class CBase58ElementsConfidentialAddress(CBase58CoinConfidentialAddress,
                                         CElementsConfidentialAddress,
                                         CBase58ElementsAddress):
    base58_prefix = bytes([4])


class CBech32ElementsAddress(CBech32CoinAddress, CElementsAddress):
    bech32_hrp = 'ert'


# CBlech32Data is not implemented
# class CBlech32ElementsConfidentialAddress(CBlech32ConfidentialAddress,
#                                           CElementsConfidentialAddress)
#    bech32_hrp = 'el'


class P2SHElementsAddress(P2SHCoinAddress, CBase58ElementsAddress):
    base58_prefix = bytes([75])


class P2PKHElementsAddress(P2PKHCoinAddress, CBase58ElementsAddress):
    base58_prefix = bytes([235])


class P2WSHElementsAddress(P2WSHCoinAddress, CBech32ElementsAddress):
    ...


class P2WPKHElementsAddress(P2WPKHCoinAddress, CBech32ElementsAddress):
    ...


class P2PKHElementsConfidentialAddress(CBase58ElementsConfidentialAddress,
                                       P2PKHCoinConfidentialAddress):
    base58_prefix = b'\x04\xEB'
    _unconfidential_address_class = P2PKHElementsAddress


P2PKHElementsAddress.register(P2PKHElementsConfidentialAddress)


class P2SHElementsConfidentialAddress(CBase58ElementsConfidentialAddress,
                                      P2SHCoinConfidentialAddress):
    base58_prefix = b'\x04\x4B'
    _unconfidential_address_class = P2SHElementsAddress


P2SHElementsAddress.register(P2SHElementsConfidentialAddress)


class CElementsKey(CCoinKey, WalletElementsClass):
    base58_prefix = bytes([239])


class CElementsExtPubKey(CCoinExtPubKey, WalletElementsClass):
    base58_prefix = b'\x04\x35\x87\xCF'


class CElementsExtKey(CCoinExtKey, WalletElementsClass):
    base58_prefix = b'\x04\x35\x83\x94'


__all__ = (
    'CConfidentialAddressError',
    'CCoinConfidentialAddress',
    'CBase58CoinConfidentialAddress',
    # 'CBlech32ConfidentialAddress',
    'P2SHCoinConfidentialAddress',
    'P2PKHCoinConfidentialAddress',
    # 'P2WSHConfidentialAddress',
    # 'P2WPKHConfidentialAddress',
    'CElementsAddress',
    'CElementsConfidentialAddress',
    'CBase58ElementsAddress',
    'CBase58ElementsConfidentialAddress',
    # 'CBech32ElementsAddress',
    # 'CBlech32ElementsConfidentialAddress',
    'P2SHElementsAddress',
    'P2PKHElementsAddress',
    'P2WSHElementsAddress',
    'P2WPKHElementsAddress',
    'P2PKHElementsConfidentialAddress',
    'P2SHElementsConfidentialAddress',
    'CElementsKey',
    'CElementsExtPubKey',
    'CElementsExtKey',
)
