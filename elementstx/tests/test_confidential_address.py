# Copyright (C) 2018 The python-bitcointx developers
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

import bitcointx
from bitcointx.core import x
from bitcointx.wallet import (
    CCoinAddress
)
from elementstx.wallet import (
    P2PKHElementsAddress,
    P2PKHElementsConfidentialAddress,
    CCoinConfidentialAddress
)


class Test_ConfidentialAddress(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._prev_chain_params = bitcointx.get_current_chain_params()
        bitcointx.select_chain_params('elements')

    @classmethod
    def tearDownClass(cls):
        bitcointx.select_chain_params(cls._prev_chain_params)

    def test(self):

        def T(confidential_addr, expected_bytes, unconfidential_addr,
              expected_blinding_pubkey, expected_class):
            a = CCoinAddress(confidential_addr)
            self.assertIsInstance(a, expected_class)
            self.assertEqual(a.to_bytes(), expected_bytes)
            self.assertEqual(unconfidential_addr, a.to_unconfidential())
            self.assertEqual(
                confidential_addr,
                str(a.__class__.from_unconfidential(
                    unconfidential_addr, a.blinding_pubkey)))
            self.assertEqual(expected_blinding_pubkey, a.blinding_pubkey)
            a2 = CCoinConfidentialAddress(str(a))
            self.assertEqual(a, a2)
            a2 = CCoinConfidentialAddress.from_unconfidential(unconfidential_addr,
                                                              a.blinding_pubkey)
            self.assertEqual(a, a2)

        T('CTEp1wviJ6U7SdAAs5sRJ1NzzRzAbmQGt1veiswjWrkzv98W7UJMQjBccafpS6v9w6evWTqeLsGc7TC1',
          x('029ffb47606c3d672a3429d91650960c63ff7d8f8ff9e00b4a8e3430c6549b4cc83422fe11c415bb9c8618f9d8498d9ad945056bdb'),
          P2PKHElementsAddress('2deBRSp69HSsJ5WAegsaksoWj8PfaQ2PqDd'),
          x('029ffb47606c3d672a3429d91650960c63ff7d8f8ff9e00b4a8e3430c6549b4cc8'),
          P2PKHElementsConfidentialAddress)
