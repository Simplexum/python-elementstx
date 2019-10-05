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

import unittest

from collections import namedtuple

from bitcointx import ChainParams, get_registered_chain_params
from bitcointx.core import Hash160, x
from bitcointx.core.script import CScript
from bitcointx.tests.test_wallet import test_address_implementations
from bitcointx.util import dispatcher_mapped_list

from bitcointx.wallet import (
    P2PKHCoinAddress, P2SHCoinAddress, P2WPKHCoinAddress, P2WSHCoinAddress,
)

from bitcointx.core.key import CPubKey

from elementstx import ElementsParams
from elementstx.wallet import (
    CCoinConfidentialAddress,
    P2PKHCoinConfidentialAddress, P2SHCoinConfidentialAddress,
    P2WPKHCoinConfidentialAddress, P2WSHCoinConfidentialAddress,
    CBase58CoinConfidentialAddress, CBlech32CoinConfidentialAddress,
    CConfidentialAddressError
)

unconf_types = ('p2pkh', 'p2sh', 'p2wpkh', 'p2wsh')
conf_types = ('conf_p2pkh', 'conf_p2sh', 'conf_p2wpkh', 'conf_p2wsh')

# NOTE: mypy cannot do dynamic fields of named tuples
AddressSamples = namedtuple('AddressSamples',  # type: ignore
                            list(unconf_types+conf_types))


def get_params_list():
    return [c for c in get_registered_chain_params()
            if issubclass(c, ElementsParams)]


def get_unconfidential_address_samples(pub1, pub2):
    return AddressSamples(
        p2pkh=P2PKHCoinAddress.from_pubkey(pub1),
        p2wpkh=P2WPKHCoinAddress.from_pubkey(pub1),
        p2sh=P2SHCoinAddress.from_redeemScript(
            CScript(b'\xa9' + Hash160(pub1) + b'\x87')),
        p2wsh=P2WSHCoinAddress.from_redeemScript(
            CScript(b'\xa9' + Hash160(pub1) + b'\x87')),
        conf_p2pkh=P2PKHCoinConfidentialAddress.from_unconfidential(
            P2PKHCoinAddress.from_pubkey(pub1), pub2),
        conf_p2wpkh=P2WPKHCoinConfidentialAddress.from_unconfidential(
            P2WPKHCoinAddress.from_pubkey(pub1), pub2),
        conf_p2sh=P2SHCoinConfidentialAddress.from_unconfidential(
            P2SHCoinAddress.from_redeemScript(
                CScript(b'\xa9' + Hash160(pub1) + b'\x87')), pub2),
        conf_p2wsh=P2WSHCoinConfidentialAddress.from_unconfidential(
            P2WSHCoinAddress.from_redeemScript(
                CScript(b'\xa9' + Hash160(pub1) + b'\x87')), pub2)
    )


class Test_ElementsAddress(unittest.TestCase):

    def test_address_implementations(self, paramclasses=None):
        def test_confidenital(aclass, pub):
            if getattr(aclass, '_unconfidential_address_class', None):
                ucaclass = aclass._unconfidential_address_class
                if getattr(ucaclass, 'from_pubkey', None):
                    a = ucaclass.from_pubkey(pub)
                else:
                    a = ucaclass.from_redeemScript(
                        CScript(b'\xa9' + Hash160(pub) + b'\x87'))

                ca = aclass.from_unconfidential(a, pub)
                self.assertEqual(ca.blinding_pubkey, pub)
                self.assertEqual(ca.to_unconfidential(), a)
                ca2 = CCoinConfidentialAddress(str(ca))
                self.assertEqual(ca, ca2)
                ca2 = CCoinConfidentialAddress.from_unconfidential(a, pub)
                self.assertEqual(ca, ca2)
                return True
            return False

        test_address_implementations(
            self, paramclasses=get_params_list(),
            extra_addr_testfunc=test_confidenital)

    def test_get_output_size(self):
        pub1 = CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'))
        pub2 = CPubKey(x('02546c76587482cd2468b76768da70c0166ecb2aa2eb1038624f4fedc138b042bc'))
        for chainparam in get_params_list():
            with ChainParams(chainparam):
                smpl = get_unconfidential_address_samples(pub1, pub2)
                # 1 byte for 'no asset', 1 byte for 'no nonce',
                # 9 bytes for explicit value,
                # minus 8 bytes of len of bitcoin nValue
                elements_unconfidential_size_extra = 1 + 1 + 9 - 8

                # 33 bytes for asset, 33 bytes for nonce,
                # 33 bytes for confidential value,
                # minus 8 bytes of len of bitcoin nValue
                elements_confidential_size_extra = 33 + 33 + 33 - 8

                self.assertEqual(smpl.p2pkh.get_output_size(), 34 + elements_unconfidential_size_extra)
                self.assertEqual(smpl.p2wpkh.get_output_size(), 31 + elements_unconfidential_size_extra)
                self.assertEqual(smpl.p2sh.get_output_size(), 32 + elements_unconfidential_size_extra)
                self.assertEqual(smpl.p2wsh.get_output_size(), 43 + elements_unconfidential_size_extra)
                self.assertEqual(smpl.conf_p2pkh.get_output_size(), 34 + elements_confidential_size_extra)
                self.assertEqual(smpl.conf_p2wpkh.get_output_size(), 31 + elements_confidential_size_extra)
                self.assertEqual(smpl.conf_p2sh.get_output_size(), 32 + elements_confidential_size_extra)
                self.assertEqual(smpl.conf_p2wsh.get_output_size(), 43 + elements_confidential_size_extra)

    def test_from_to_unconfidential(self):  #noqa
        pub1 = CPubKey(x('02546c76587482cd2468b76768da70c0166ecb2aa2eb1038624f4fedc138b042bc'))
        pub2 = CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'))
        params_list = get_params_list()
        for pl_index, chainparam in enumerate(params_list):
            next_chainparam = (params_list[0] if pl_index + 1 == len(params_list)
                               else params_list[pl_index+1])
            with ChainParams(chainparam):
                mapped_cls_list = dispatcher_mapped_list(CCoinConfidentialAddress)
                assert len(mapped_cls_list) == 1
                chain_specific_cls = mapped_cls_list[0]
                with ChainParams(next_chainparam):
                    mapped_cls_list = dispatcher_mapped_list(CCoinConfidentialAddress)
                    assert len(mapped_cls_list) == 1
                    next_chain_specific_cls = mapped_cls_list[0]
                    assert next_chain_specific_cls is not chain_specific_cls
                smpl = get_unconfidential_address_samples(pub1, pub2)
                for uct in unconf_types:
                    for ct in conf_types:
                        unconf = getattr(smpl, uct)
                        conf = getattr(smpl, ct)
                        with self.assertRaises(TypeError):
                            next_chain_specific_cls.from_unconfidential(unconf, pub2)

                        if ct.endswith(uct):
                            self.assertEqual(str(conf.to_unconfidential()), str(unconf))
                            self.assertEqual(str(conf.from_unconfidential(unconf, pub2)), str(conf))
                            self.assertNotEqual(str(conf.from_unconfidential(unconf, pub1)), str(conf))
                            self.assertEqual(str(CCoinConfidentialAddress.from_unconfidential(unconf, pub2)),
                                             str(conf))
                            self.assertEqual(str(chain_specific_cls.from_unconfidential(unconf, pub2)),
                                             str(conf))
                            if ct.endswith('p2pkh'):
                                self.assertEqual(
                                    str(CBase58CoinConfidentialAddress.from_unconfidential(unconf, pub2)),
                                    str(conf))
                                self.assertEqual(
                                    str(P2PKHCoinConfidentialAddress.from_unconfidential(unconf, pub2)),
                                    str(conf))
                            elif ct.endswith('p2sh'):
                                self.assertEqual(
                                    str(CBase58CoinConfidentialAddress.from_unconfidential(unconf, pub2)),
                                    str(conf))
                                self.assertEqual(
                                    str(P2SHCoinConfidentialAddress.from_unconfidential(unconf, pub2)),
                                    str(conf))
                            elif ct.endswith('p2wpkh'):
                                self.assertEqual(
                                    str(CBlech32CoinConfidentialAddress.from_unconfidential(unconf, pub2)),
                                    str(conf))
                                self.assertEqual(
                                    str(P2WPKHCoinConfidentialAddress.from_unconfidential(unconf, pub2)),
                                    str(conf))
                            elif ct.endswith('p2wsh'):
                                self.assertEqual(
                                    str(CBlech32CoinConfidentialAddress.from_unconfidential(unconf, pub2)),
                                    str(conf))
                                self.assertEqual(
                                    str(P2WSHCoinConfidentialAddress.from_unconfidential(unconf, pub2)),
                                    str(conf))
                            else:
                                assert 0, "unexpected addr type"

                            if issubclass(conf.__class__, CBlech32CoinConfidentialAddress):
                                with self.assertRaises(CConfidentialAddressError):
                                    CBase58CoinConfidentialAddress.from_unconfidential(unconf, pub2)
                            elif issubclass(conf.__class__, CBase58CoinConfidentialAddress):
                                with self.assertRaises(CConfidentialAddressError):
                                    CBlech32CoinConfidentialAddress.from_unconfidential(unconf, pub2)
                            else:
                                assert 0, "unexpected conf.__class__"

                            for ct2 in conf_types:
                                if ct != ct2:
                                    conf_cls = getattr(smpl, ct2).__class__
                                    with self.assertRaises(TypeError):
                                        conf_cls.from_unconfidential(unconf, pub2)
                        else:
                            self.assertNotEqual(str(conf.to_unconfidential()), str(unconf))
                            with self.assertRaises(TypeError):
                                conf.from_unconfidential(unconf, pub2)
