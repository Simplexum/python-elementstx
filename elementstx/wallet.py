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

from io import BytesIO
from typing import Union, List, TypeVar, Type

from bitcointx.core.key import (
    CPubKey
)
from bitcointx.core.script import CScript
from bitcointx.wallet import (
    WalletCoinClassDispatcher, WalletCoinClass,
    CCoinAddress, P2SHCoinAddress, P2WSHCoinAddress,
    P2PKHCoinAddress, P2WPKHCoinAddress,
    CBase58CoinAddress, CBech32CoinAddress,
    CCoinAddressError,
    CCoinKey, CCoinExtKey, CCoinExtPubKey
)
from bitcointx.util import (
    dispatcher_mapped_list, ensure_isinstance, ClassMappingDispatcher
)
from .core import (
    CoreElementsClassDispatcher, CElementsTxOut,
    CConfidentialCommitmentBase, CConfidentialValue, CConfidentialAsset,
    CConfidentialNonce
)
import elementstx.blech32


class WalletElementsClassDispatcher(WalletCoinClassDispatcher,
                                    depends=[CoreElementsClassDispatcher]):
    ...


class WalletElementsClass(WalletCoinClass,
                          metaclass=WalletElementsClassDispatcher):
    ...


class WalletElementsLiquidV1ClassDispatcher(WalletElementsClassDispatcher,
                                            depends=[CoreElementsClassDispatcher]):
    ...


class WalletElementsLiquidV1Class(WalletCoinClass,
                                  metaclass=WalletElementsLiquidV1ClassDispatcher):
    ...


class CConfidentialAddressError(CCoinAddressError):
    """Raised when an invalid confidential address is encountered"""


T_CCoinConfidentialAddress = TypeVar('T_CCoinConfidentialAddress',
                                     bound='CCoinConfidentialAddress')


class CCoinConfidentialAddress(CCoinAddress):

    @classmethod
    def from_unconfidential(
        cls: Type[T_CCoinConfidentialAddress], unconfidential_adr: CCoinAddress,
        blinding_pubkey: Union[CPubKey, bytes, bytearray]
    ) -> T_CCoinConfidentialAddress:
        """Convert unconfidential address to confidential

        Raises CConfidentialAddressError if blinding_pubkey is invalid
        (CConfidentialAddressError is a subclass of CCoinAddressError)

        unconfidential_adr can be string or CBase58CoinAddress
        instance. blinding_pubkey must be a bytes instance
        """
        ensure_isinstance(blinding_pubkey, (CPubKey, bytes, bytearray),
                          'blinding_pubkey')
        if not isinstance(blinding_pubkey, CPubKey):
            blinding_pubkey = CPubKey(blinding_pubkey)
        if not blinding_pubkey.is_fullyvalid():
            raise ValueError('invalid blinding pubkey')

        # without #noqa linter gives warning that we should use isinstance.
        # but here we want exact match, isinstance is not applicable
        if type(cls) is not type(unconfidential_adr.__class__): #noqa
            raise TypeError(
                'cannot create {} from {}: this address class might belong '
                'to different chain'
                .format(cls.__name__, unconfidential_adr.__class__.__name__))

        clsmap = {
            P2PKHCoinAddress: P2PKHCoinConfidentialAddress,
            P2WPKHCoinAddress: P2WPKHCoinConfidentialAddress,
            P2SHCoinAddress: P2SHCoinConfidentialAddress,
            P2WSHCoinAddress: P2WSHCoinConfidentialAddress,
        }
        for unconf_cls, conf_cls in clsmap.items():
            mapped_cls_list = dispatcher_mapped_list(conf_cls)
            if mapped_cls_list:
                if len(mapped_cls_list) != 1:
                    raise TypeError(
                        f"{conf_cls.__name__} must be final dispatch class")
                chain_specific_conf_cls = mapped_cls_list[0]
            else:
                chain_specific_conf_cls = conf_cls
            if isinstance(unconfidential_adr, unconf_cls) and\
                    (issubclass(cls, (conf_cls, chain_specific_conf_cls))
                     or issubclass(chain_specific_conf_cls, cls)):
                return conf_cls.from_bytes(blinding_pubkey + unconfidential_adr)
            if issubclass(cls, (conf_cls, chain_specific_conf_cls)):
                raise TypeError(
                    'cannot create {} from {}: only subclasses of {} are accepted'
                    .format(cls.__name__,
                            unconfidential_adr.__class__.__name__,
                            unconf_cls.__name__))

        raise CConfidentialAddressError(
            'cannot create {} from {}: no matching confidential address class'
            .format(cls.__name__, unconfidential_adr.__class__.__name__))

    def to_unconfidential(self) -> CCoinAddress:
        # NOTE: this assert also makes mypy ignore that
        # _unconfidential_address_class is not declared
        # for CCoinConfidentialAddress. But this is OK, because declaring
        # it will require to convert CCoinConfidentialAddress to generic class,
        # and is not convenient, and not gives much in correctness.
        assert isinstance(self, bytes), \
            "descendant classes must also be bytes subclasses"
        return self._unconfidential_address_class.from_bytes(self[33:])

    @property
    def blinding_pubkey(self) -> CPubKey:
        assert isinstance(self, bytes), \
            "descendant classes must also be bytes subclasses"
        return CPubKey(self[0:33])

    # NOTE: The return type is CScript here, because is we make
    # it CElementsScript, that would become incompatible with CCoinAddress,
    # and we would need to type:ignore all the CCoinAddress subclasses below.
    # The proper way might be to make CCoinAddress a generic class, and
    # specify concrete CScript subclass when defining the address subclasses.
    # but this would make defining address classes less convenient -- each
    # address class declaration would need to specify which script class
    # it returns.
    def to_scriptPubKey(self) -> CScript:
        return self.to_unconfidential().to_scriptPubKey()

    def to_redeemScript(self) -> CScript:
        return self.to_unconfidential().to_scriptPubKey()

    def from_scriptPubKey(self) -> None:  # type: ignore
        raise CCoinAddressError(
            'cannot create confidential address from scriptPubKey')

    @classmethod
    def get_output_size(cls_or_inst) -> int:
        if isinstance(cls_or_inst, type):
            cls = cls_or_inst
            data_length = getattr(cls, '_data_length', None)
            if not data_length:
                raise TypeError('output size is not available for {}'
                                .format(cls.__name__))
            inst = cls.from_bytes(b'\x00'*data_length)
        else:
            inst = cls_or_inst
        dummy_commitment = b'\x00'*CConfidentialCommitmentBase._committedSize
        txo = CElementsTxOut(scriptPubKey=inst.to_scriptPubKey(),
                             nValue=CConfidentialValue(dummy_commitment),
                             nAsset=CConfidentialAsset(dummy_commitment),
                             nNonce=CConfidentialNonce(dummy_commitment))
        f = BytesIO()
        txo.stream_serialize(f)
        return len(f.getbuffer())


class CBase58CoinConfidentialAddress(CCoinConfidentialAddress, CBase58CoinAddress):
    ...


class CBlech32AddressError(CCoinAddressError):
    """Raised when an invalid blech32-encoded address is encountered"""


class P2WSHCoinConfidentialAddressError(CBlech32AddressError):
    """Raised when an invalid P2SH confidential address is encountered"""


class P2WPKHCoinConfidentialAddressError(CBlech32AddressError):
    """Raised when an invalid P2PKH confidential address is encountered"""


T_CBlech32DataDispatched = TypeVar('T_CBlech32DataDispatched',
                                   bound='CBlech32DataDispatched')


class CBlech32DataDispatched(elementstx.blech32.CBlech32Data):

    def __init__(self, _s: str) -> None:
        if self.__class__.blech32_witness_version < 0:
            raise TypeError(
                f'{self.__class__.__name__} must not be instantiated directly')
        if len(self) != self.__class__._data_length:
            raise TypeError(
                f'lengh of the data is not {self.__class__._data_length}')

    @classmethod
    def blech32_get_match_candidates(
        cls: Type[T_CBlech32DataDispatched]
    ) -> List[Type[T_CBlech32DataDispatched]]:
        assert isinstance(cls, ClassMappingDispatcher)
        candidates = dispatcher_mapped_list(cls)
        if not candidates:
            if cls.blech32_witness_version < 0:
                raise TypeError(
                    "if class has no dispatched descendants, it must have "
                    "blech32_witness_version set to non-negative value")
            candidates = [cls]
        return candidates


class CBlech32CoinConfidentialAddress(CBlech32DataDispatched,
                                      CCoinConfidentialAddress):
    """A Blech32-encoded coin confidential address"""

    _data_length: int
    blech32_witness_version: int


class P2SHCoinConfidentialAddress(CBase58CoinConfidentialAddress,
                                  next_dispatch_final=True):
    _data_length = 20 + 33


class P2PKHCoinConfidentialAddress(CBase58CoinConfidentialAddress,
                                   next_dispatch_final=True):
    _data_length = 20 + 33


class P2WSHCoinConfidentialAddress(CBlech32CoinConfidentialAddress,
                                   next_dispatch_final=True):
    _data_length = 32 + 33
    blech32_witness_version = 0
    _scriptpubkey_type = 'witness_v0_scripthash'


class P2WPKHCoinConfidentialAddress(CBlech32CoinConfidentialAddress,
                                    next_dispatch_final=True):
    _data_length = 20 + 33
    blech32_witness_version = 0
    _scriptpubkey_type = 'witness_v0_keyhash'


class CElementsAddressBase(CCoinAddress):
    @classmethod
    def get_output_size(cls_or_inst) -> int:
        if isinstance(cls_or_inst, type):
            cls = cls_or_inst
            data_length = getattr(cls, '_data_length', None)
            if not data_length:
                raise TypeError('output size is not available for {}'
                                .format(cls.__name__))
            inst = cls.from_bytes(b'\x00'*data_length)
        else:
            inst = cls_or_inst
        txo = CElementsTxOut(scriptPubKey=inst.to_scriptPubKey(),
                             nValue=CConfidentialValue(0))
        f = BytesIO()
        txo.stream_serialize(f)
        return len(f.getbuffer())


class CElementsAddress(CElementsAddressBase, WalletElementsClass):
    ...


class CElementsConfidentialAddress(CCoinConfidentialAddress, CElementsAddress):
    ...


class CBase58ElementsAddress(CBase58CoinAddress, CElementsAddress):
    ...


class CBase58ElementsConfidentialAddress(CBase58CoinConfidentialAddress,
                                         CElementsConfidentialAddress,
                                         CBase58ElementsAddress):
    ...


class CBech32ElementsAddress(CBech32CoinAddress, CElementsAddress):
    bech32_hrp = 'ert'


class CBlech32ElementsConfidentialAddress(CBlech32CoinConfidentialAddress,
                                          CElementsConfidentialAddress):
    blech32_hrp = 'el'


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

    base58_prefix = bytes([4, 235])
    _unconfidential_address_class = P2PKHElementsAddress


P2PKHElementsAddress.register(P2PKHElementsConfidentialAddress)


class P2SHElementsConfidentialAddress(CBase58ElementsConfidentialAddress,
                                      P2SHCoinConfidentialAddress):
    base58_prefix = bytes([4, 75])
    _unconfidential_address_class = P2SHElementsAddress


P2SHElementsAddress.register(P2SHElementsConfidentialAddress)


class P2WPKHElementsConfidentialAddress(CBlech32ElementsConfidentialAddress,
                                        P2WPKHCoinConfidentialAddress):
    _unconfidential_address_class = P2WPKHElementsAddress


P2WPKHElementsAddress.register(P2WPKHElementsConfidentialAddress)


class P2WSHElementsConfidentialAddress(CBlech32ElementsConfidentialAddress,
                                       P2WSHCoinConfidentialAddress):
    _unconfidential_address_class = P2WSHElementsAddress


P2WSHElementsAddress.register(P2WSHElementsConfidentialAddress)


class CElementsKey(CCoinKey, WalletElementsClass):
    base58_prefix = bytes([239])


class CElementsExtPubKey(CCoinExtPubKey, WalletElementsClass):
    base58_prefix = b'\x04\x35\x87\xCF'


class CElementsExtKey(CCoinExtKey, WalletElementsClass):
    base58_prefix = b'\x04\x35\x83\x94'


class CElementsLiquidV1Address(CElementsAddressBase, WalletElementsLiquidV1Class):
    ...


class CElementsLiquidV1ConfidentialAddress(CCoinConfidentialAddress, CElementsLiquidV1Address):
    ...


class CBase58ElementsLiquidV1Address(CBase58CoinAddress, CElementsLiquidV1Address):
    ...


class CBase58ElementsLiquidV1ConfidentialAddress(CBase58CoinConfidentialAddress,
                                                 CElementsLiquidV1ConfidentialAddress,
                                                 CBase58ElementsLiquidV1Address):
    ...


class CBech32ElementsLiquidV1Address(CBech32CoinAddress, CElementsLiquidV1Address):
    bech32_hrp = 'ex'


class CBlech32ElementsLiquidV1ConfidentialAddress(CBlech32CoinConfidentialAddress,
                                                  CElementsLiquidV1ConfidentialAddress):
    blech32_hrp = 'lq'


class P2SHElementsLiquidV1Address(P2SHCoinAddress, CBase58ElementsLiquidV1Address):
    base58_prefix = bytes([39])


class P2PKHElementsLiquidV1Address(P2PKHCoinAddress, CBase58ElementsLiquidV1Address):
    base58_prefix = bytes([57])


class P2WSHElementsLiquidV1Address(P2WSHCoinAddress, CBech32ElementsLiquidV1Address):
    ...


class P2WPKHElementsLiquidV1Address(P2WPKHCoinAddress, CBech32ElementsLiquidV1Address):
    ...


class P2PKHElementsLiquidV1ConfidentialAddress(CBase58ElementsLiquidV1ConfidentialAddress,
                                               P2PKHCoinConfidentialAddress):
    base58_prefix = bytes([12, 57])
    _unconfidential_address_class = P2PKHElementsLiquidV1Address


class P2SHElementsLiquidV1ConfidentialAddress(CBase58ElementsLiquidV1ConfidentialAddress,
                                              P2SHCoinConfidentialAddress):
    base58_prefix = bytes([12, 39])
    _unconfidential_address_class = P2SHElementsLiquidV1Address


class P2WPKHElementsLiquidV1ConfidentialAddress(CBlech32ElementsLiquidV1ConfidentialAddress,
                                                P2WPKHCoinConfidentialAddress):
    _unconfidential_address_class = P2WPKHElementsLiquidV1Address


class P2WSHElementsLiquidV1ConfidentialAddress(CBlech32ElementsLiquidV1ConfidentialAddress,
                                               P2WSHCoinConfidentialAddress):
    _unconfidential_address_class = P2WSHElementsLiquidV1Address


class CElementsLiquidV1Key(CCoinKey, WalletElementsLiquidV1Class):
    base58_prefix = bytes([239])


class CElementsLiquidV1ExtPubKey(CCoinExtPubKey, WalletElementsLiquidV1Class):
    base58_prefix = b'\x04\x88\xB2\x1E'


class CElementsLiquidV1ExtKey(CCoinExtKey, WalletElementsLiquidV1Class):
    base58_prefix = b'\x04\x88\xAD\xE4'


__all__ = (
    'CConfidentialAddressError',
    'CCoinConfidentialAddress',
    'CBase58CoinConfidentialAddress',
    'CBlech32CoinConfidentialAddress',
    'P2SHCoinConfidentialAddress',
    'P2PKHCoinConfidentialAddress',
    'P2WSHCoinConfidentialAddress',
    'P2WPKHCoinConfidentialAddress',
    'CElementsAddress',
    'CElementsConfidentialAddress',
    'CBase58ElementsAddress',
    'CBase58ElementsConfidentialAddress',
    'CBech32ElementsAddress',
    'CBlech32ElementsConfidentialAddress',
    'P2SHElementsAddress',
    'P2PKHElementsAddress',
    'P2WSHElementsAddress',
    'P2WPKHElementsAddress',
    'P2PKHElementsConfidentialAddress',
    'P2SHElementsConfidentialAddress',
    'CElementsKey',
    'CElementsExtPubKey',
    'CElementsExtKey',
    'CElementsLiquidV1Address',
    'CElementsLiquidV1ConfidentialAddress',
    'CBase58ElementsLiquidV1Address',
    'CBase58ElementsLiquidV1ConfidentialAddress',
    'CBech32ElementsLiquidV1Address',
    'CBlech32ElementsLiquidV1ConfidentialAddress',
    'P2SHElementsLiquidV1Address',
    'P2PKHElementsLiquidV1Address',
    'P2WSHElementsLiquidV1Address',
    'P2WPKHElementsLiquidV1Address',
    'P2PKHElementsLiquidV1ConfidentialAddress',
    'P2SHElementsLiquidV1ConfidentialAddress',
    'CElementsLiquidV1Key',
    'CElementsLiquidV1ExtPubKey',
    'CElementsLiquidV1ExtKey',
)
