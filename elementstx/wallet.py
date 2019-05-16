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

from threading import local

from bitcointx.core import AddressEncodingError
from bitcointx.core.key import (
    CPubKey
)
from bitcointx.util import make_frontend_metaclass

from bitcointx.wallet import (
    CoinWalletIdentityMeta,
    CCoinAddress, P2SHCoinAddress, P2WSHCoinAddress,
    P2PKHCoinAddress, P2WPKHCoinAddress,
    CBase58CoinAddress, CBech32CoinAddress,
    CBase58CoinAddressCommon, CBech32CoinAddressCommon,
    CBase58CoinKeyBase, CBase58CoinExtPubKeyBase, CBase58CoinExtKeyBase,
    CCoinAddressBase, CCoinAddressError,
    P2SHCoinAddressCommon, P2PKHCoinAddressCommon,
    P2WSHCoinAddressCommon, P2WPKHCoinAddressCommon,
    CCoinKey, CCoinExtKey, CCoinExtPubKey
)

from bitcointx.core.script import CScript
from .core.script import CElementsScript

_thread_local = local()
_frontend_metaclass = make_frontend_metaclass('_ElementsWallet', _thread_local)


class CConfidentialAddressError(CCoinAddressError):
    """Raised when an invalid confidential address is encountered"""


class ElementsWalletIdentityMeta(CoinWalletIdentityMeta):

    @classmethod
    def _get_required_classes(cls):
        main_classes, extra_classes = \
            super(cls, ElementsWalletIdentityMeta)._get_required_classes()
        main_classes.add(CConfidentialAddress)
        main_classes.add(CBase58ConfidentialAddress)
        main_classes.add(P2SHConfidentialAddress)
        main_classes.add(P2PKHConfidentialAddress)
        return main_classes, extra_classes

    @classmethod
    def _get_extra_classmap(cls):
        return {CScript: CElementsScript}


class CConfidentialAddress(metaclass=_frontend_metaclass):
    ...


class CBase58ConfidentialAddress(metaclass=_frontend_metaclass):
    ...


class P2SHConfidentialAddress(metaclass=_frontend_metaclass):
    ...


class P2PKHConfidentialAddress(metaclass=_frontend_metaclass):
    ...


class CConfidentialAddressBase:

    def __new__(cls, s):
        for enc_class in cls._get_encoding_address_classes():
            try:
                return enc_class(s)
            except AddressEncodingError:
                pass

        raise CCoinAddressError(
            'Unrecognized encoding for {}' .format(cls.__name__))

    @classmethod
    def _get_encoding_address_classes(cls):
        return (cls._concrete_class.CBase58ConfidentialAddress, )

    @classmethod
    def from_unconfidential(cls, unconfidential_adr, blinding_pubkey):
        """Convert unconfidential address to confidential

        Raises CConfidentialAddressError if blinding_pubkey is invalid
        (CConfidentialAddressError is a subclass of CCoinAddressError)

        unconfidential_adr can be string or CBase58CoinAddressCommon
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
            print(unconfidential_adr.__class__)
            raise CConfidentialAddressError(
                'non-base58 confidential addresses are not supported for now')

        for enc_cls in cls._get_encoding_address_classes():
            if issubclass(enc_cls, CBase58CoinAddress):
                for b58cls in enc_cls._get_base58_address_classes():
                    if len(b58cls.base58_prefix) > 1 and \
                            unconfidential_adr.base58_prefix == b58cls.base58_prefix[1:]:
                        return b58cls.from_bytes(blinding_pubkey + unconfidential_adr)

        raise CConfidentialAddressError(
            'cannot create {} from {}: cannot find matching confidential address class'
            .format(cls, unconfidential_adr.__class__.__name__))

    def to_unconfidential(self):
        return self.__class__._unconfidential_address_class.from_bytes(self[33:])

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


class CElementsConfidentialAddress(CConfidentialAddressBase,
                                   metaclass=ElementsWalletIdentityMeta):
    ...


class CElementsAddress(CCoinAddressBase,
                       metaclass=ElementsWalletIdentityMeta):
    ...


class CBase58ElementsAddress(CBase58CoinAddressCommon, CElementsAddress):
    @classmethod
    def _get_base58_address_classes(cls):
        unconf = super(
            cls, CBase58ElementsAddress)._get_base58_address_classes()
        return (cls._concrete_class.P2SHConfidentialAddress,
                cls._concrete_class.P2PKHConfidentialAddress) + unconf


class CBase58ElementsConfidentialAddress(CConfidentialAddressBase,
                                         CBase58CoinAddressCommon,
                                         CElementsAddress):
    base58_prefix = bytes([4])

    @classmethod
    def _get_base58_address_classes(cls):
        return (cls._concrete_class.P2SHConfidentialAddress,
                cls._concrete_class.P2PKHConfidentialAddress)


class CBech32ElementsAddress(CBech32CoinAddressCommon, CElementsAddress):
    bech32_hrp = 'ert'


# CBlech32Data is not implemented
# class CBlech32ElementsConfidentialAddress(CElementsConfidentialAddress,
#                                           CElementsAddress):
#    bech32_hrp = 'el'


class P2SHElementsAddress(P2SHCoinAddressCommon, CBase58ElementsAddress):
    base58_prefix = bytes([75])


class P2PKHElementsAddress(P2PKHCoinAddressCommon, CBase58ElementsAddress):
    base58_prefix = bytes([235])


class P2WSHElementsAddress(P2WSHCoinAddressCommon, CBech32ElementsAddress):
    ...


class P2WPKHElementsAddress(P2WPKHCoinAddressCommon, CBech32ElementsAddress):
    ...


class P2PKHElementsConfidentialAddress(CElementsConfidentialAddress,
                                       CBase58ElementsAddress):
    base58_prefix = b'\x04\xEB'
    _unconfidential_address_class = P2PKHElementsAddress


class P2SHElementsConfidentialAddress(CElementsConfidentialAddress,
                                      CBase58ElementsAddress):
    base58_prefix = b'\x04\x4B'
    _unconfidential_address_class = P2SHElementsAddress


class CElementsKey(CBase58CoinKeyBase,
                   metaclass=ElementsWalletIdentityMeta):
    base58_prefix = bytes([239])


class CElementsExtPubKey(CBase58CoinExtPubKeyBase,
                         metaclass=ElementsWalletIdentityMeta):
    base58_prefix = b'\x04\x35\x87\xCF'


class CElementsExtKey(CBase58CoinExtKeyBase,
                      metaclass=ElementsWalletIdentityMeta):
    base58_prefix = b'\x04\x35\x83\x94'


CBase58CoinAddress.register(CBase58ConfidentialAddress)

ElementsWalletIdentityMeta.set_classmap({
    CCoinAddress: CElementsAddress,
    CConfidentialAddress: CElementsConfidentialAddress,
    P2SHConfidentialAddress: P2SHElementsConfidentialAddress,
    P2PKHConfidentialAddress: P2PKHElementsConfidentialAddress,
    CBase58ConfidentialAddress: CBase58ElementsConfidentialAddress,
    # CBlech32ConfidentialAddress: CBlech32ElementsConfidentialAddress,
    CBase58CoinAddress: CBase58ElementsAddress,
    CBech32CoinAddress: CBech32ElementsAddress,
    P2SHCoinAddress: P2SHElementsAddress,
    P2PKHCoinAddress: P2PKHElementsAddress,
    P2WSHCoinAddress: P2WSHElementsAddress,
    P2WPKHCoinAddress: P2WPKHElementsAddress,
    CCoinKey: CElementsKey,
    CCoinExtKey: CElementsExtKey,
    CCoinExtPubKey: CElementsExtPubKey,
})

ElementsWalletIdentityMeta.activate(_thread_local)
