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

from bitcointx.core import Hash160
from bitcointx.core.script import CScript
from bitcointx.tests.test_wallet import Test_CCoinAddress

from elementstx import ElementsParams


class Test_ElementsAddress(Test_CCoinAddress):

    def test_address_implementations(self, paramclasses=None):
        def test_confidenital(cclass, identity, pub):
            aclass = identity._clsmap[cclass]
            script_class = identity._clsmap[CScript]
            if getattr(aclass, 'from_unconfidential', None):
                caclass = aclass
                aclass = aclass._unconfidential_address_class

                if getattr(aclass, 'from_pubkey', None):
                    a = aclass.from_pubkey(pub)
                else:
                    a = aclass.from_redeemScript(
                        script_class(b'\xa9' + Hash160(pub) + b'\x87'))

                ca = caclass.from_unconfidential(a, pub)
                self.assertEqual(ca.blinding_pubkey, pub)
                self.assertEqual(ca.to_unconfidential(), a)
                return True
            return False

        super(
            Test_ElementsAddress, self
        ).test_address_implementations(paramclasses=[ElementsParams],
                                       extra_addr_testfunc=test_confidenital)
