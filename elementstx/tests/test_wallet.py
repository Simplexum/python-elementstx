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

from bitcointx.core import Hash160
from bitcointx.core.script import CScript
from bitcointx.tests.test_wallet import test_address_implementations

from elementstx import ElementsParams
from elementstx.wallet import CCoinConfidentialAddress


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
