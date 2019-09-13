#!/usr/bin/env python3
#
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

# This code loads raw transaction an the blinding key from two separate files,
# and then tries to unblind vouts of the transaction with this blinding keys.
# normally, only one vout would be unblinded.

# pylama:ignore=E501

import sys

from bitcointx import select_chain_params
from bitcointx.core import x, CTransaction, satoshi_to_coins
from bitcointx.wallet import CCoinKey, CCoinAddress
from elementstx.wallet import CCoinConfidentialAddress


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("usage: {} <raw-hex-tx-file> <blinding-key-file>"
              .format(sys.argv[0]))
        sys.exit(-1)

    # Switch the chain parameters to Elements
    select_chain_params('elements')

    # Read in and decode the blinded transaction.
    # expected to be hex-encoded as one line.
    with open(sys.argv[1]) as f:
        tx = CTransaction.deserialize(x(f.readline().rstrip()))

    # Read in the blinding key, expected to be in WIF format.
    with open(sys.argv[2]) as f:
        bkey = CCoinKey.from_secret_bytes(x(f.readline().rstrip()))

    # Iterate through transaction ouptputs, and unblind what we can.
    print("")
    for n, vout in enumerate(tx.vout):
        # Note that nValue of vout in Elements is not a simple int,
        # but CConfidentialValue, which can either be explicit, and can be
        # converted to satoshis with to_amount(), or it can be blinded, in
        # which case you need to unblind the output to know its value.
        if vout.nValue.is_explicit():
            # The output is not blinded, we can access the values right away
            assert vout.nAsset.is_explicit(), "unblinding just the asset is not supported"
            if vout.is_fee():
                print("vout {}: fee".format(n))
            else:
                print("vout {}: explicit".format(n))
                print("  destination address:",
                      CCoinAddress.from_scriptPubKey(tx.vout[n].scriptPubKey))
            print("  amount:\t\t", satoshi_to_coins(vout.nValue.to_amount()))
            print("  asset:\t\t", vout.nAsset.to_asset())
        else:
            # Try to unblind the output with the given blinding key
            result = vout.unblind_confidential_pair(
                bkey, tx.wit.vtxoutwit[n].rangeproof)

            if result.error:
                # Nope, our blinding key is not good for this output
                print("vout {}: cannot unblind: {}".format(n, result.error))
                print("  destination address:",
                      CCoinAddress.from_scriptPubKey(tx.vout[n].scriptPubKey))
                if not tx.wit.is_null():
                    rpinfo = tx.wit.vtxoutwit[n].get_rangeproof_info()
                    if rpinfo:
                        print('  ct-exponent', rpinfo.exp)
                        print('  ct-bits', rpinfo.mantissa)
                        print('  value-minimum',
                              satoshi_to_coins(rpinfo.value_min, check_range=False))
                        print('  value-maximum',
                              satoshi_to_coins(rpinfo.value_max, check_range=False))
            else:
                # Successfully unblinded the output !
                print("vout {}: unblinded".format(n))
                addr = CCoinAddress.from_scriptPubKey(tx.vout[n].scriptPubKey)
                conf_addr = CCoinConfidentialAddress.from_unconfidential(addr, bkey.pub)
                print("  destination address:")
                print("     confidential:\t", conf_addr)
                print("     unconfidential:\t", addr)
                print("  amount:\t\t", satoshi_to_coins(result.amount))
                print("  blinding_factor:\t", result.blinding_factor)
                print("  asset:\t\t", result.asset)
                print("  asset_blinding_factor:", result.asset_blinding_factor)
        print("")
