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

from bitcointx import ChainParams
from bitcointx.core import Hash160, x
from bitcointx.core.script import CScript
from bitcointx.tests.test_wallet import test_address_implementations

from bitcointx.wallet import (
    P2PKHCoinAddress, P2SHCoinAddress, P2WPKHCoinAddress, P2WSHCoinAddress,
)

from bitcointx.core.key import CPubKey

from elementstx import ElementsParams
from elementstx.wallet import (
    CCoinConfidentialAddress,
    P2PKHCoinConfidentialAddress, P2SHCoinConfidentialAddress,
    # P2WPKHCoinConfidentialAddress, P2WSHCoinConfidentialAddress
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

        test_address_implementations(self, paramclasses=[ElementsParams],
                                     extra_addr_testfunc=test_confidenital)

    def test_get_output_size(self):

        with ChainParams('elements'):
            # 1 byte for 'no asset', 1 byte for 'no nonce',
            # 9 bytes for explicit value,
            # minus 8 bytes of len of bitcoin nValue
            elements_unconfidential_size_extra = 1 + 1 + 9 - 8

            # 33 bytes for asset, 33 bytes for nonce,
            # 33 bytes for confidential value,
            # minus 8 bytes of len of bitcoin nValue
            elements_confidential_size_extra = 33 + 33 + 33 - 8

            pub = CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'))
            a = P2PKHCoinAddress.from_pubkey(pub)
            self.assertEqual(a.get_output_size(), 34 + elements_unconfidential_size_extra)
            a = P2WPKHCoinAddress.from_pubkey(pub)
            self.assertEqual(a.get_output_size(), 31 + elements_unconfidential_size_extra)
            a = P2SHCoinAddress.from_redeemScript(
                CScript(b'\xa9' + Hash160(pub) + b'\x87'))
            self.assertEqual(a.get_output_size(), 32 + elements_unconfidential_size_extra)
            a = P2WSHCoinAddress.from_redeemScript(
                CScript(b'\xa9' + Hash160(pub) + b'\x87'))
            self.assertEqual(a.get_output_size(), 43 + elements_unconfidential_size_extra)

            a = P2PKHCoinConfidentialAddress.from_unconfidential(
                P2PKHCoinAddress.from_pubkey(pub), pub)
            self.assertEqual(a.get_output_size(), 34 + elements_confidential_size_extra)

#            a = P2WPKHCoinConfidentialAddress.from_unconfidential(
#                P2WPKHCoinAddress.from_pubkey(pub), pub)
#            self.assertEqual(a.get_output_size(), 31 + elements_confidential_size_extra)

            a = P2SHCoinConfidentialAddress.from_unconfidential(
                P2SHCoinAddress.from_redeemScript(
                    CScript(b'\xa9' + Hash160(pub) + b'\x87')), pub)

            self.assertEqual(a.get_output_size(), 32 + elements_confidential_size_extra)

#            a = P2WSHCoinConfidentialAddress.from_unconfidential(
#                P2WSHCoinAddress.from_redeemScript(
#                    CScript(b'\xa9' + Hash160(pub) + b'\x87')), pub)
#            self.assertEqual(a.get_output_size(), 43 + elements_confidential_size_extra)
