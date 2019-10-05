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

import os
import json
import random
import logging
import unittest

import bitcointx
from bitcointx.core import (
    x, lx, b2lx, b2x, Uint256, coins_to_satoshi,
    CTransaction, CMutableTransaction,
    COutPoint, CTxIn, CTxOut, CTxWitness,
    CMutableTxOut, CMutableTxIn, CMutableTxWitness,
    CMutableOutPoint, CTxInWitness, CMutableTxInWitness,
    CTxOutWitness, CMutableTxOutWitness
)
from bitcointx.core.script import (
    CScript, OP_RETURN, SignatureHash,
    SIGHASH_ALL, SIGVERSION_BASE, OP_CHECKMULTISIG,
    CScriptWitness
)
from bitcointx.core.scripteval import VerifyScript
from bitcointx.core.key import CPubKey, CKey
from bitcointx.wallet import (
    CCoinAddress, CCoinKey,
    P2PKHCoinAddress, P2SHCoinAddress
)
from elementstx.core import (
    CAsset, CConfidentialValue, CConfidentialAsset, CConfidentialNonce,
    calculate_asset, generate_asset_entropy, calculate_reissuance_token,
    CElementsTransaction, CElementsMutableTransaction,
    BlindingInputDescriptor
)
from elementstx.wallet import (
    P2PKHElementsAddress, P2SHElementsAddress
)
from elementstx.core.secp256k1 import secp256k1_has_zkp

zkp_unavailable_warning_shown = False


def warn_zkp_unavailable():
    global zkp_unavailable_warning_shown
    if not zkp_unavailable_warning_shown:
        log = logging.getLogger("Test_Elements_CTransaction")
        log.warning(' secp256k1-zkp unavailable')
        log.warning(' skipping rangeproof checks.')
        log.warning(' If you do not need Elements blind/unblind funcionality, it is safe to ignore this warning.')
        zkp_unavailable_warning_shown = True


def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for tx_decoded in json.load(fd):
            if isinstance(tx_decoded, str):
                continue  # skip comment
            tx_bytes = x(tx_decoded['hex'])
            assert len(tx_bytes) == tx_decoded['size']
            tx = CTransaction.deserialize(tx_bytes)
            yield (tx_decoded, tx, tx_bytes)


class ElementsTestSetupBase():
    @classmethod
    def setUpClass(cls):
        logging.basicConfig()
        cls._prev_chain_params = bitcointx.get_current_chain_params()
        bitcointx.select_chain_params('elements')

    @classmethod
    def tearDownClass(cls):
        bitcointx.select_chain_params(cls._prev_chain_params)


class Test_CTxIn(ElementsTestSetupBase, unittest.TestCase):
    def test_is_final(self):
        self.assertTrue(CTxIn().is_final())
        self.assertTrue(CTxIn(nSequence=0xffffffff).is_final())
        self.assertFalse(CTxIn(nSequence=0).is_final())

    def test_repr(self):
        def T(txin, expected):
            actual = repr(txin)
            self.assertEqual(actual, expected)
        T(CTxIn(),
          'CElementsTxIn(CElementsOutPoint(), CElementsScript([]), 0xffffffff, CAssetIssuance(), is_pegin=False)')

    def test_immutable(self):
        """CTxIn shall not be mutable"""
        txin = CTxIn()
        with self.assertRaises(AttributeError):
            txin.nSequence = 1


class Test_CMutableTxIn(ElementsTestSetupBase, unittest.TestCase):
    def test_GetHash(self):
        """CMutableTxIn.GetHash() is not cached"""
        txin = CMutableTxIn()

        h1 = txin.GetHash()
        txin.prevout.n = 1

        self.assertNotEqual(h1, txin.GetHash())

    def test_repr(self):
        def T(txin, expected):
            actual = repr(txin)
            self.assertEqual(actual, expected)
        T(CMutableTxIn(),
          'CElementsMutableTxIn(CElementsMutableOutPoint(), CElementsScript([]), 0xffffffff, CAssetIssuance(), is_pegin=False)')


class Test_CTxOut(ElementsTestSetupBase, unittest.TestCase):
    def test_repr(self):
        def T(txout, expected):
            actual = repr(txout)
            self.assertEqual(actual, expected)
        T(CTxOut(),
          "CElementsTxOut(CConfidentialValue(x('')), CElementsScript([]), CConfidentialAsset(x('')), CConfidentialNonce(x('')))")

    def test_immutable(self):
        """CTxIn shall not be mutable"""
        txout = CTxOut()
        with self.assertRaises(AttributeError):
            txout.nValue = None


class Test_CMutableTxOut(ElementsTestSetupBase, unittest.TestCase):
    def test_repr(self):
        def T(txout, expected):
            actual = repr(txout)
            self.assertEqual(actual, expected)
        T(CMutableTxOut(),
          "CElementsMutableTxOut(CConfidentialValue(x('')), CElementsScript([]), CConfidentialAsset(x('')), CConfidentialNonce(x('')))")

    def test_mutable(self):
        """CTxIn shall be mutable"""
        txout = CMutableTxOut()
        txout.nValue = None


class Test_Elements_CTransaction(ElementsTestSetupBase, unittest.TestCase):
    def test_is_coinbase(self):
        tx = CMutableTransaction()
        self.assertFalse(tx.is_coinbase())

        tx.vin.append(CMutableTxIn())

        # IsCoinBase() in reference client doesn't check if vout is empty
        self.assertTrue(tx.is_coinbase())

        tx.vin[0].prevout.n = 0
        self.assertFalse(tx.is_coinbase())

        tx.vin[0] = CTxIn()
        tx.vin.append(CTxIn())
        self.assertFalse(tx.is_coinbase())

    def test_immutable(self):
        tx = CTransaction()
        self.assertFalse(tx.is_coinbase())

        # check that immutable property holds
        with self.assertRaises(AttributeError):
            tx.nVersion = 2
        with self.assertRaises(AttributeError):
            tx.vin.append(CTxIn())

        mtx = tx.to_mutable()
        mtx.nVersion = 2
        mtx.vin.append(CTxIn())

        itx = tx.to_immutable()

        with self.assertRaises(AttributeError):
            itx.nVersion = 2
        with self.assertRaises(AttributeError):
            itx.vin.append(CTxIn())

    def test_serialize_deserialize(self):
        for tx_decoded, tx, tx_bytes in load_test_vectors('elements_txs.json'):
            self.check_serialize_deserialize(tx, tx_bytes, tx_decoded)

    def check_serialize_deserialize(self, tx, tx_bytes, tx_decoded):
            self.assertEqual(tx_bytes, tx.serialize())
            self.assertEqual(tx_bytes, CTransaction.deserialize(tx.serialize()).serialize())
            self.assertEqual(tx_bytes, tx.to_mutable().to_immutable().serialize())
            self.assertEqual(tx_decoded['version'], tx.nVersion)
            self.assertEqual(tx_decoded['locktime'], tx.nLockTime)
            # we ignore withash field - we do not have ComputeWitnessHash() function
            # as it is only relevant for blocks, not transactions
            self.assertEqual(tx_decoded['hash'], b2lx(tx.GetHash()))
            self.assertEqual(tx_decoded['txid'], b2lx(tx.GetTxid()))
            for n, vout in enumerate(tx_decoded['vout']):
                if 'amountcommitment' in vout:
                    self.assertEqual(x(vout['amountcommitment']),
                                     tx.vout[n].nValue.commitment)
                if 'assetcommitment' in vout:
                    self.assertEqual(x(vout['assetcommitment']),
                                     tx.vout[n].nAsset.commitment)
                if 'asset' in vout:
                    self.assertEqual(vout['asset'], tx.vout[n].nAsset.to_asset().to_hex())
                if 'scriptPubKey' in vout:
                    spk = vout['scriptPubKey']
                    self.assertEqual(x(spk['hex']), tx.vout[n].scriptPubKey)

                    if 'pegout_type' in spk:
                        self.assertEqual(spk['type'], 'nulldata')
                        self.assertTrue(tx.vout[n].scriptPubKey.is_pegout())
                        genesis_hash, pegout_scriptpubkey = tx.vout[n].scriptPubKey.get_pegout_data()
                        if spk['pegout_type'] != 'nonstandard':
                            assert spk['pegout_type'] in ('pubkeyhash', 'scripthash')
                            addr = CCoinAddress.from_scriptPubKey(pegout_scriptpubkey)
                            self.assertEqual(len(spk['pegout_addresses']), 1)
                            self.assertEqual(spk['pegout_addresses'][0], str(addr))
                        self.assertEqual(spk['pegout_hex'], b2x(pegout_scriptpubkey))
                        self.assertEqual(spk['pegout_chain'], b2lx(genesis_hash))

                    if spk['type'] in ('pubkeyhash', 'scripthash'):
                        self.assertEqual(len(spk['addresses']), 1)
                        addr = CCoinAddress.from_scriptPubKey(tx.vout[n].scriptPubKey)
                        self.assertEqual(spk['addresses'][0], str(addr))
                    elif spk['type'] == 'nulldata':
                        self.assertEqual(tx.vout[n].scriptPubKey, x(spk['hex']))
                    else:
                        self.assertEqual(spk['type'], 'fee')
                        self.assertEqual(len(tx.vout[n].scriptPubKey), 0)

                if secp256k1_has_zkp:
                    if tx.wit.is_null():
                        rpinfo = None
                    else:
                        rpinfo = tx.wit.vtxoutwit[n].get_rangeproof_info()
                    if 'value-minimum' in vout:
                        self.assertIsNotNone(rpinfo)
                        self.assertEqual(vout['ct-exponent'], rpinfo.exp)
                        self.assertEqual(vout['ct-bits'], rpinfo.mantissa)
                        self.assertEqual(coins_to_satoshi(vout['value-minimum'], check_range=False),
                                         rpinfo.value_min)
                        self.assertEqual(coins_to_satoshi(vout['value-maximum'], check_range=False),
                                         rpinfo.value_max)
                    else:
                        self.assertTrue(rpinfo is None or rpinfo.exp == -1)
                        if rpinfo is None:
                            value = tx.vout[n].nValue.to_amount()
                        else:
                            value = rpinfo.value_min
                        self.assertEqual(coins_to_satoshi(vout['value']), value)
                else:
                    warn_zkp_unavailable()
                    if 'value' in vout and tx.vout[n].nValue.is_explicit():
                        self.assertEqual(coins_to_satoshi(vout['value']), tx.vout[n].nValue.to_amount())

            for n, vin in enumerate(tx_decoded['vin']):
                if 'scripSig' in vin:
                    self.assertEqual(x(vin['scriptSig']['hex'], tx.vin[n].scriptSig))
                if 'txid' in vin:
                    self.assertEqual(vin['txid'], b2lx(tx.vin[n].prevout.hash))
                if 'vout' in vin:
                    self.assertEqual(vin['vout'], tx.vin[n].prevout.n)
                if 'is_pegin' in vin:
                    self.assertEqual(vin['is_pegin'], tx.vin[n].is_pegin)
                    if vin['is_pegin'] is False:
                        if 'scriptWitness' in vin:
                            self.assertTrue(tx.wit.vtxinwit[n].scriptWitness.is_null())
                        if 'pegin_witness' in vin:
                            self.assertTrue(tx.wit.vtxinwit[n].pegin_witness.is_null())
                    else:
                        for stack_index, stack_item in enumerate(vin['scriptWitness']):
                            self.assertTrue(
                                stack_item,
                                b2x(tx.wit.vtxinwit[n].scriptWitness.stack[stack_index]))
                        for stack_index, stack_item in enumerate(vin['pegin_witness']):
                            self.assertTrue(
                                stack_item,
                                b2x(tx.wit.vtxinwit[n].pegin_witness.stack[stack_index]))
                if 'sequence' in vin:
                    self.assertEqual(vin['sequence'], tx.vin[n].nSequence)
                if 'coinbase' in vin:
                    self.assertTrue(tx.is_coinbase())
                if 'issuance' in vin:
                    iss = vin['issuance']
                    self.assertEqual(iss['assetBlindingNonce'],
                                     tx.vin[n].assetIssuance.assetBlindingNonce.to_hex())
                    if 'asset' in iss:
                        if iss['isreissuance']:
                            self.assertTrue(not tx.vin[n].assetIssuance.assetBlindingNonce.is_null())
                            self.assertEqual(iss['assetEntropy'],
                                             tx.vin[n].assetIssuance.assetEntropy.to_hex())
                            asset = calculate_asset(tx.vin[n].assetIssuance.assetEntropy)
                        else:
                            entropy = generate_asset_entropy(tx.vin[n].prevout,
                                                             tx.vin[n].assetIssuance.assetEntropy)
                            self.assertEqual(iss['assetEntropy'], entropy.to_hex())
                            asset = calculate_asset(entropy)
                            reiss_token = calculate_reissuance_token(
                                entropy, tx.vin[n].assetIssuance.nAmount.is_commitment())
                            self.assertEqual(iss['token'], reiss_token.to_hex())
                        self.assertEqual(iss['asset'], asset.to_hex())
                    if 'assetamount' in iss:
                        self.assertEqual(coins_to_satoshi(iss['assetamount']),
                                         tx.vin[n].assetIssuance.nAmount.to_amount())
                    elif 'assetamountcommitment' in iss:
                        self.assertEqual(iss['assetamountcommitment'],
                                         b2x(tx.vin[n].assetIssuance.nAmount.commitment))
                    if 'tokenamount' in iss:
                        self.assertEqual(coins_to_satoshi(iss['tokenamount']),
                                         tx.vin[n].assetIssuance.nInflationKeys.to_amount())
                    elif 'tokenamountcommitment' in iss:
                        self.assertEqual(iss['tokenamountcommitment'],
                                         b2x(tx.vin[n].assetIssuance.nInflationKeys.commitment))

    def check_blind(self, unblinded_tx, unblinded_tx_raw, blinded_tx, blinded_tx_raw, bundle,
                    blinding_derivation_key, asset_commitments=()):
        input_descriptors = []
        for utxo in bundle['vin_utxo']:
            amount = -1 if utxo['amount'] == -1 else coins_to_satoshi(utxo['amount'])
            input_descriptors.append(
                BlindingInputDescriptor(amount=amount,
                                        asset=CAsset(lx(utxo['asset'])),
                                        blinding_factor=Uint256(lx(utxo['blinder'])),
                                        asset_blinding_factor=Uint256(lx(utxo['assetblinder'])))
            )

        num_to_blind = 0
        output_pubkeys = []
        for vout in unblinded_tx.vout:
            if not vout.nNonce.is_null() and vout.nValue.is_explicit():
                output_pubkeys.append(CPubKey(vout.nNonce.commitment))
                num_to_blind += 1
            else:
                output_pubkeys.append(CPubKey())

        tx_to_blind = unblinded_tx.to_mutable()

        blind_issuance_asset_keys = []
        blind_issuance_token_keys = []
        for vin in blinded_tx.vin:
            issuance = vin.assetIssuance
            if not issuance.is_null():
                issuance_blinding_script = CScript([OP_RETURN, vin.prevout.hash, vin.prevout.n])
                blind_issuance_key = issuance_blinding_script.derive_blinding_key(blinding_derivation_key)
                if issuance.nAmount.is_commitment():
                    blind_issuance_asset_keys.append(blind_issuance_key)
                    num_to_blind += 1
                else:
                    blind_issuance_asset_keys.append(None)
                if issuance.nInflationKeys.is_commitment():
                    blind_issuance_token_keys.append(blind_issuance_key)
                    num_to_blind += 1
                else:
                    blind_issuance_token_keys.append(None)
            else:
                blind_issuance_asset_keys.append(None)
                blind_issuance_token_keys.append(None)

        # Deterministic random was used when generating test transactions,
        # to have reproducible results. We need to set the random seed
        # to the same value that was used when test data was generated.
        # (see note below on that supplying _rand_func parameter to blind()
        #  is intended only for testing code, not for production)
        random.seed(bundle['rand_seed'])

        def rand_func(n):
            return bytes([random.randint(0, 255) for _ in range(n)])

        # Auxiliary generators will be be non-empty only for the case
        # when we are blinding different transaction templates that is
        # then combined into one common transaction, that is done in
        # test_split_blinding_multi_sign().
        # In this case, you need to supply the asset commitments for
        # all of the inputs of the final transaction, even if currently
        # blinded transaction template does not contain these inputs.
        blind_result = tx_to_blind.blind(
            input_descriptors=input_descriptors,
            output_pubkeys=output_pubkeys,
            blind_issuance_asset_keys=blind_issuance_asset_keys,
            blind_issuance_token_keys=blind_issuance_token_keys,
            auxiliary_generators=asset_commitments,

            # IMPORTANT NOTE:
            # Specifying custom _rand_func is only required for testing.
            # Here we use it to supply deterministically generated
            # pseudo-random bytes, so that blinding results will match the test
            # data that was generated using deterministically generated random
            # bytes, with seed values that are saved in 'rand_seed' fields of
            # test data bunldes.
            #
            # In normal code you do should NOT specify _rand_func:
            # os.urandom will be used by default (os.urandom is suitable for cryptographic use)
            _rand_func=rand_func
        )

        self.assertFalse(blind_result.error)

        if all(_k is None for _k in blind_issuance_asset_keys):
            random.seed(bundle['rand_seed'])
            tx_to_blind2 = unblinded_tx.to_mutable()
            blind_result2 = tx_to_blind2.blind(
                input_descriptors=input_descriptors,
                output_pubkeys=output_pubkeys,
                blind_issuance_asset_keys=blind_issuance_asset_keys,
                blind_issuance_token_keys=blind_issuance_token_keys,
                auxiliary_generators=asset_commitments,
                _rand_func=rand_func
            )
            self.assertFalse(blind_result2.error)
            self.assertEqual(blind_result, blind_result2)
            self.assertEqual(tx_to_blind.serialize(), tx_to_blind2.serialize())

        self.assertEqual(blind_result.num_successfully_blinded, num_to_blind)
        self.assertNotEqual(unblinded_tx_raw, tx_to_blind.serialize())
        self.assertEqual(blinded_tx_raw, tx_to_blind.serialize())

    def check_unblind(self, unblinded_tx, unblinded_tx_raw, blinded_tx, blinded_tx_raw,
                      bundle, blinding_derivation_key):
        for n, bvout in enumerate(blinded_tx.vout):
            uvout = unblinded_tx.vout[n]

            if not uvout.nValue.is_explicit():
                # skip confidential vouts of partially-blinded txs
                continue

            self.assertEqual(bvout.scriptPubKey, uvout.scriptPubKey)
            if bvout.nAsset.is_explicit():
                self.assertTrue(bvout.nValue.is_explicit())
                self.assertEqual(bvout.nValue.to_amount(), uvout.nValue.to_amount())
                self.assertEqual(bvout.nAsset.to_asset().data, uvout.nAsset.to_asset().data)
                self.assertEqual(bvout.nNonce.commitment, uvout.nNonce.commitment)
            else:
                self.assertFalse(bvout.nValue.is_explicit())

                for fbk, spk_set in bundle['foreign_blinding_keys'].items():
                    if b2x(bvout.scriptPubKey) in spk_set:
                        blinding_key = uvout.scriptPubKey.derive_blinding_key(CKey(lx(fbk)))
                        break
                else:
                    blinding_key = uvout.scriptPubKey.derive_blinding_key(blinding_derivation_key)

                unblind_result = bvout.unblind_confidential_pair(
                    blinding_key=blinding_key,
                    rangeproof=blinded_tx.wit.vtxoutwit[n].rangeproof)

                self.assertFalse(unblind_result.error)
                self.assertEqual(uvout.nValue.to_amount(), unblind_result.amount)
                self.assertEqual(uvout.nAsset.to_asset().data, unblind_result.asset.data)
                descr = unblind_result.get_descriptor()

                self.assertIsInstance(descr, BlindingInputDescriptor)
                self.assertEqual(descr.amount, unblind_result.amount)
                self.assertEqual(descr.asset, unblind_result.asset)
                self.assertEqual(descr.blinding_factor,
                                 unblind_result.blinding_factor)
                self.assertEqual(descr.asset_blinding_factor,
                                 unblind_result.asset_blinding_factor)

                ub_info = bundle['unblinded_vout_info'][n]
                if len(ub_info):
                    self.assertEqual(coins_to_satoshi(ub_info['amount']), unblind_result.amount)
                    self.assertEqual(ub_info['asset'], unblind_result.asset.to_hex())
                    self.assertEqual(ub_info['blinding_factor'],
                                     unblind_result.blinding_factor.to_hex())
                    self.assertEqual(ub_info['asset_blinding_factor'],
                                     unblind_result.asset_blinding_factor.to_hex())

    def check_sign(self, blinded_tx, signed_tx, bundle):
        tx_to_sign = blinded_tx.to_mutable()
        for n, vin in enumerate(tx_to_sign.vin):
            utxo = bundle['vin_utxo'][n]
            amount = -1 if utxo['amount'] == -1 else coins_to_satoshi(utxo['amount'])

            scriptPubKey = CScript(x(utxo['scriptPubKey']))
            a = CCoinAddress(utxo['address'])
            if 'privkey' in utxo:
                privkey = CCoinKey(utxo['privkey'])
                assert isinstance(a, P2PKHCoinAddress),\
                    "only P2PKH is supported for single-sig"
                assert a == P2PKHElementsAddress.from_pubkey(privkey.pub)
                assert scriptPubKey == a.to_scriptPubKey()
                sighash = SignatureHash(scriptPubKey, tx_to_sign, n, SIGHASH_ALL,
                                        amount=amount, sigversion=SIGVERSION_BASE)
                sig = privkey.sign(sighash) + bytes([SIGHASH_ALL])
                tx_to_sign.vin[n].scriptSig = CScript([CScript(sig), CScript(privkey.pub)])
            else:
                pk_list = [CCoinKey(pk) for pk in utxo['privkey_list']]
                redeem_script = [utxo['num_p2sh_participants']]
                redeem_script.extend([pk.pub for pk in pk_list])
                redeem_script.extend([len(pk_list), OP_CHECKMULTISIG])
                redeem_script = CScript(redeem_script)
                assert isinstance(a, P2SHCoinAddress),\
                    "only P2SH is supported for multi-sig."
                assert scriptPubKey == redeem_script.to_p2sh_scriptPubKey()
                assert a == P2SHElementsAddress.from_scriptPubKey(
                    redeem_script.to_p2sh_scriptPubKey())
                sighash = SignatureHash(redeem_script, tx_to_sign, n, SIGHASH_ALL,
                                        amount=amount, sigversion=SIGVERSION_BASE)
                sigs = [pk.sign(sighash) + bytes([SIGHASH_ALL]) for pk in pk_list]
                tx_to_sign.vin[n].scriptSig = CScript([0] + sigs + [redeem_script])

            VerifyScript(tx_to_sign.vin[n].scriptSig, scriptPubKey, tx_to_sign, n, amount=amount)

        self.assertEqual(tx_to_sign.serialize(), signed_tx.serialize())

    def test_blind_unnblind_sign(self):
        if not secp256k1_has_zkp:
            warn_zkp_unavailable()
            return

        with open(os.path.dirname(__file__)
                  + '/data/elements_txs_blinding.json', 'r') as fd:
            for bundle in json.load(fd):
                blinded_tx_raw = x(bundle['blinded']['hex'])
                blinded_tx = CTransaction.deserialize(blinded_tx_raw)
                self.assertEqual(blinded_tx.serialize(), blinded_tx_raw)
                self.check_serialize_deserialize(blinded_tx, blinded_tx_raw, bundle['blinded'])
                unblinded_tx_raw = x(bundle['unblinded']['hex'])
                unblinded_tx = CTransaction.deserialize(unblinded_tx_raw)

                self.assertEqual(unblinded_tx.serialize(), unblinded_tx_raw)
                self.check_serialize_deserialize(unblinded_tx, unblinded_tx_raw, bundle['unblinded'])
                signed_tx_raw = x(bundle['signed_hex'])
                signed_tx = CTransaction.deserialize(signed_tx_raw)
                self.assertEqual(signed_tx.serialize(), signed_tx_raw)
                blinding_derivation_key = CKey(lx(bundle['blinding_derivation_key']))

                # ensure that str and repr works
                for f in (str, repr):
                    f(unblinded_tx)
                    f(blinded_tx)
                    f(signed_tx)

                if len(blinded_tx.vout) != len(unblinded_tx.vout):
                    assert len(blinded_tx.vout) == len(unblinded_tx.vout) + 1
                    assert blinded_tx.vout[-1].scriptPubKey == b'\x6a',\
                        "expected last output of blinded tx to be OP_RETURN"
                    scriptPubKey = CScript([OP_RETURN])
                    unblinded_tx = unblinded_tx.to_mutable()
                    unblinded_tx.vout.append(
                        CMutableTxOut(
                            nValue=CConfidentialValue(0),
                            nAsset=CConfidentialAsset(unblinded_tx.vout[-1].nAsset.to_asset()),
                            nNonce=CConfidentialNonce(
                                scriptPubKey.derive_blinding_key(blinding_derivation_key).pub),
                            scriptPubKey=scriptPubKey))
                    unblinded_tx = unblinded_tx.to_immutable()
                    unblinded_tx_raw = unblinded_tx.serialize()

                self.check_blind(unblinded_tx, unblinded_tx_raw,
                                 blinded_tx, blinded_tx_raw,
                                 bundle, blinding_derivation_key)

                self.check_unblind(unblinded_tx, unblinded_tx_raw,
                                   blinded_tx, blinded_tx_raw,
                                   bundle, blinding_derivation_key)

                self.check_sign(blinded_tx, signed_tx, bundle)

    def test_split_blinding_multi_sign(self):
        if not secp256k1_has_zkp:
            warn_zkp_unavailable()
            return

        with open(os.path.dirname(__file__)
                  + '/data/elements_txs_split_blinding.json', 'r') as fd:
            split_blind_txdata = json.load(fd)
            # we need to supply asset commitments from all inputs of the final
            # tranaction to the blinding function, even if we are blinding a tx
            # template that does not contain these inputs
            asset_commitments = [x(utxo['assetcommitment'])
                                 for utxo in split_blind_txdata['tx2']['vin_utxo']]

            for txlabel in ('tx1', 'tx2'):
                bundle = split_blind_txdata[txlabel]
                blinded_tx_raw = x(bundle['blinded']['hex'])
                blinded_tx = CTransaction.deserialize(blinded_tx_raw)
                self.assertEqual(blinded_tx.serialize(), blinded_tx_raw)
                self.check_serialize_deserialize(blinded_tx, blinded_tx_raw, bundle['blinded'])
                unblinded_tx_raw = x(bundle['unblinded']['hex'])
                unblinded_tx = CTransaction.deserialize(unblinded_tx_raw)

                self.assertEqual(unblinded_tx.serialize(), unblinded_tx_raw)
                self.check_serialize_deserialize(unblinded_tx, unblinded_tx_raw, bundle['unblinded'])
                if 'signed_hex' in bundle:
                    signed_tx_raw = x(bundle['signed_hex'])
                    signed_tx = CTransaction.deserialize(signed_tx_raw)
                    self.assertEqual(signed_tx.serialize(), signed_tx_raw)
                else:
                    signed_tx = None

                blinding_derivation_key = CKey(lx(bundle['blinding_derivation_key']))

                self.check_blind(unblinded_tx, unblinded_tx_raw,
                                 blinded_tx, blinded_tx_raw,
                                 bundle, blinding_derivation_key,
                                 asset_commitments=asset_commitments)

                self.check_unblind(unblinded_tx, unblinded_tx_raw,
                                   blinded_tx, blinded_tx_raw,
                                   bundle, blinding_derivation_key)

                if signed_tx is not None:
                    self.check_sign(blinded_tx, signed_tx, bundle)

    # We need to do the same mutable/immutable tests as with bitcoin transactions,
    # because the implementation for the transaction parts are different,
    # there are extra fields used, etc.
    def test_mutable_tx_creation_with_immutable_parts_specified(self):
        tx = CMutableTransaction(
            vin=[CTxIn(prevout=COutPoint(hash=b'a'*32, n=0))],
            vout=[CTxOut()],
            witness=CTxWitness(vtxinwit=[CTxInWitness()],
                               vtxoutwit=[CTxOutWitness()]))

        self.assertIsInstance(tx, CElementsMutableTransaction)

        def check_mutable_parts(tx):
            self.assertTrue(tx.vin[0].is_mutable())
            self.assertTrue(tx.vin[0].prevout.is_mutable())
            self.assertTrue(tx.vout[0].is_mutable())
            self.assertTrue(tx.wit.is_mutable())
            self.assertTrue(tx.wit.vtxinwit[0].is_mutable())
            self.assertTrue(tx.wit.vtxoutwit[0].is_mutable())

        check_mutable_parts(tx)

        # Test that if we deserialize with CMutableTransaction,
        # all the parts are mutable
        tx = CMutableTransaction.deserialize(tx.serialize())
        check_mutable_parts(tx)

        # Test some parts separately, because when created via
        # CMutableTransaction instantiation, they are created with from_*
        # methods, and not directly

        txin = CMutableTxIn(prevout=COutPoint(hash=b'a'*32, n=0))
        self.assertTrue(txin.prevout.is_mutable())

        wit = CMutableTxWitness((CTxInWitness(),), (CTxOutWitness(),))
        self.assertTrue(wit.vtxinwit[0].is_mutable())
        self.assertTrue(wit.vtxoutwit[0].is_mutable())

    def test_immutable_tx_creation_with_mutable_parts_specified(self):
        tx = CTransaction(
            vin=[CMutableTxIn(prevout=COutPoint(hash=b'a'*32, n=0))],
            vout=[CMutableTxOut()],
            witness=CMutableTxWitness(
                [CMutableTxInWitness(CScriptWitness([CScript([0])]))],
                [CMutableTxOutWitness()]))

        self.assertIsInstance(tx, CElementsTransaction)

        def check_immutable_parts(tx):
            self.assertTrue(not tx.vin[0].is_mutable())
            self.assertTrue(not tx.vin[0].prevout.is_mutable())
            self.assertTrue(not tx.vout[0].is_mutable())
            self.assertTrue(not tx.wit.is_mutable())
            self.assertTrue(not tx.wit.vtxinwit[0].is_mutable())
            self.assertTrue(not tx.wit.vtxoutwit[0].is_mutable())

        check_immutable_parts(tx)

        # Test that if we deserialize with CTransaction,
        # all the parts are immutable
        tx = CTransaction.deserialize(tx.serialize())
        check_immutable_parts(tx)

        # Test some parts separately, because when created via
        # CMutableTransaction instantiation, they are created with from_*
        # methods, and not directly

        txin = CTxIn(prevout=CMutableOutPoint(hash=b'a'*32, n=0))
        self.assertTrue(not txin.prevout.is_mutable())

        wit = CTxWitness((CMutableTxInWitness(),), (CMutableTxOutWitness(),))
        self.assertTrue(not wit.vtxinwit[0].is_mutable())
        self.assertTrue(not wit.vtxoutwit[0].is_mutable())
