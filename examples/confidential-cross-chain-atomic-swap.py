#!/usr/bin/env python3
#
# Copyright (C) 2018 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# This code spawns two processes, one connects to Elements daemon,
# another one - to Bitcoin daemon.
# Then these two processes communicate with each other to prepare
# a transaction that atomically swaps their assets, while the transactions
# on both sides cannot be linked by outside observers, other than
# by the timing of the transactions.
# This is because the keys used in the swap are blinded with additional
# key that only the participants of the swap know.

# NOTE: the code may fail for various reasons, and
# not claim/recover the funds.
# In real application, all the state that is needed to
# claim/recover should be reliably saved to be able to retry
# the claim or claim-back attempt.
# In this example, for the sake of simplicity,
# we do not save any state, and thus if something unexpected happens,
# the program will exit and the funds will may be left unclaimed/unrecovered.

import os
import sys
import time
import ecdsa
import signal
import hashlib
import traceback

from multiprocessing import Process, Pipe, Lock

from bitcointx import select_chain_params, ChainParams
from bitcointx.rpc import RPCCaller, JSONRPCError
from bitcointx.core import (
    x, lx, b2x, coins_to_satoshi, satoshi_to_coins,
    CTransaction, CMutableTransaction, CBitcoinTransaction,
    CTxIn, CTxOut, COutPoint, CTxInWitness
)
from bitcointx.core.script import (
    CBitcoinScript,
    SIGHASH_ALL, SIGVERSION_BASE, SIGVERSION_WITNESS_V0,

    OP_IF, OP_ELSE, OP_ENDIF,
    OP_SWAP, OP_DROP, OP_CAT,
    OP_CHECKSIG, OP_CHECKSEQUENCEVERIFY,
    OP_RETURN, OP_TRUE, OP_FALSE
)

from bitcointx.core.key import CPubKey, CKey
from bitcointx.core.script import CScriptWitness, DATA

from bitcointx.wallet import (
    CCoinAddress, P2SHCoinAddress, P2WSHCoinAddress
)

from elementstx.core import (
    CAsset, CConfidentialValue, CConfidentialAsset,
    CConfidentialNonce, BlindingInputDescriptor,
    CElementsTransaction
)

from elementstx.core.script import CElementsScript, OP_CHECKSIGFROMSTACKVERIFY

from elementstx.wallet import (
    CCoinConfidentialAddress, CElementsConfidentialAddress,
    CElementsAddress, P2SHCoinConfidentialAddress
)

# A global lock variable to coordinate console output between
# child processes. We could pass the lock as arguments to the
# process functions, but it is simpler to make it global var
# and not clutter the participant process funcs with unneeded details
console_lock = None

# The asset that represents L-BTC.
# It will be specified on the command line when the example is run.
bitcoin_asset = None

bitcoin_chain_name = 'bitcoin/regtest'
elements_chain_name = 'elements'

# Bob sends bitcoin first, and Alice sends Elements BTC asset.
# Alice's timeout must be less than Bob's, and if Bob does not
# send his spend-reveal transaction before Alice's timeout expires,
# she reclaims her asset and the swap aborts. If Alice's timeout
# would be bigger than Bob's, then Bob can reclaim his BTC, and claim Alice's
# asset after that, effectively stealing it.
# Also note, that our 'miner' process generates bitcoin and elements blocks
# with equal intervals. In real world (Bitcoin and Liquid, for example)
# the block times will differ significantly (both interval and variation).
# These timeouts should be long enough for real use, and take into
# account all the properies of real-life blockchain systems.
bitcoin_contract_timeout = 15
elements_contract_timeout = 10

# For simplicity, the amount to swap is fixed beforehand
pre_agreed_amount = 1.01

# For simplicity, we use fixed fee
fixed_fee_amount = 0.01

# will be overwritten by participants.
# OK to use tha same global variable for both participants,
# because participants run in separate processes.
last_wish_func = None

ansi_colors = {
    'alice': '\033[1;32m',  # green
    'bob': '\033[1;35m'  # purple
}
end_color = '\033[0m'


def alice(say, recv, send, die, btc_rpc, elt_rpc):
    """A function that implements the logic
    of the Elements-side participant
    of confidential cross-chain atomic swap"""

    global last_wish_func

    # Default chain for Alice will be Elements
    # To handle bitcoin-related objects, either
    # `with ChainParams(bitcoin_chain_name):` have to be used, or
    # concrete classes, like CBitcoinAddress, CBitcoinTransaction, etc.
    select_chain_params(elements_chain_name)

    # Let's create the shared blinding key
    blinding_key = CKey.from_secret_bytes(os.urandom(32))
    # And the key for btc spend
    alice_btc_key = CKey.from_secret_bytes(os.urandom(32))
    # And the key for the 'timeout' branch of the contract
    alice_elt_exit_key = CKey.from_secret_bytes(os.urandom(32))

    say('Sending pubkeys to Bob')
    send('pubkeys', (alice_btc_key.pub, alice_elt_exit_key.pub))

    say('Sending the blinding key to Bob')
    send('blinding_key', blinding_key.secret_bytes)

    (contract_pubkey_raw,
     bob_elt_pubkey_raw,
     bob_btc_exit_pub_raw) = recv('pubkeys')

    say("Pubkey of the key to be revealed: {}"
        .format(b2x(contract_pubkey_raw)))
    say("Bob's Elements-side pubkey: {}".format(b2x(bob_elt_pubkey_raw)))

    contract_pubkey = CPubKey(contract_pubkey_raw)

    key_to_reveal_pub = CPubKey.add(contract_pubkey, blinding_key.pub)

    elt_contract = make_elt_cntract(key_to_reveal_pub,
                                    bob_elt_pubkey_raw, alice_elt_exit_key.pub)

    elt_contract_addr = P2SHCoinAddress.from_redeemScript(elt_contract)

    confidential_contract_addr = P2SHCoinConfidentialAddress.from_unconfidential(
        elt_contract_addr, blinding_key.pub)
    assert isinstance(confidential_contract_addr, CElementsConfidentialAddress)

    say("Created Elemets-side swap contract, size: {}"
        .format(len(elt_contract)))
    say("Contract address:\n\tconfidential: {}\n\tunconfidential: {}"
        .format(confidential_contract_addr, elt_contract_addr))

    btc_txid = recv('btc_txid')

    combined_btc_spend_pubkey = CPubKey.add(contract_pubkey,
                                            alice_btc_key.pub)
    btc_contract = make_btc_contract(combined_btc_spend_pubkey,
                                     bob_btc_exit_pub_raw)

    tx_json = btc_rpc.getrawtransaction(btc_txid, 1)

    if tx_json['confirmations'] < 6:
        die('Transaction does not have enough confirmations')

    # We use ChainParams, and not P2WSHBitcoinAddress here,
    # because bitcoin_chain_name might be 'bitcoin/regtest', for example,
    # and then the address would need to be P2WSHBitcoinRegtestAddress.
    # with ChainParams we leverage the 'frontend class' magic, P2WSHCoinAddress
    # will give us appropriate instance.
    with ChainParams(bitcoin_chain_name):
        btc_contract_addr = P2WSHCoinAddress.from_redeemScript(btc_contract)
        say('Looking for this address in transaction {} in Bitcoin'
            .format(btc_txid))

    # CTransaction subclasses do not change between mainnet/testnet/regtest,
    # so we can directly use CBitcoinTransaction.
    # That might not be true for other chains, though.
    # You might also want to use CTransaction within `with ChainParams(...):`
    btc_tx = CBitcoinTransaction.deserialize(x(tx_json['hex']))

    for n, vout in enumerate(btc_tx.vout):
        if vout.scriptPubKey == btc_contract_addr.to_scriptPubKey():
            say("Found the address at output {}".format(n))
            btc_vout_n = n
            break
    else:
        die('Did not find contract address in transaction')

    if vout.nValue != coins_to_satoshi(pre_agreed_amount):
        die('the amount {} found at the output in the offered transaction '
            'does not match the expected amount {}'
            .format(satoshi_to_coins(vout.nValue), pre_agreed_amount))

    say('Bitcoin amount match expected values')

    say('Sending {} to {}'.format(pre_agreed_amount,
                                  confidential_contract_addr))
    contract_txid = elt_rpc.sendtoaddress(str(confidential_contract_addr),
                                          pre_agreed_amount)

    def alice_last_wish_func():
        try_reclaim_elt(say, elt_rpc, contract_txid, elt_contract,
                        alice_elt_exit_key, blinding_key, die)

    last_wish_func = alice_last_wish_func

    wait_confirm(say, 'Elements', contract_txid, die, elt_rpc,
                 num_confirms=2)

    send('elt_txid', contract_txid)

    sr_txid = wait_spend_reveal_transaction(say, contract_txid, die, elt_rpc)

    say('Got txid for spend-reveal transaction from Bob ({})'.format(sr_txid))

    tx_json = elt_rpc.getrawtransaction(sr_txid, 1)

    wait_confirm(say, 'Elements', sr_txid, die, elt_rpc, num_confirms=2)

    sr_tx = CTransaction.deserialize(x(tx_json['hex']))

    for n, vin in enumerate(sr_tx.vin):
        if vin.prevout.hash == lx(contract_txid)\
                and vin.scriptSig[-(len(elt_contract)):] == elt_contract:
            say('Transaction input {} seems to contain a script '
                'we can recover the key from'.format(n))
            reveal_script_iter = iter(vin.scriptSig)
            break
    else:
        die('Spend-reveal transaction does not have input that spends '
            'the contract output')

    next(reveal_script_iter)  # skip Bob's spend signature

    try:
        # 2 skipped bytes are tag and len
        sig_s = ecdsa.util.string_to_number(next(reveal_script_iter)[2:])
    except (ValueError, StopIteration):
        die('Reveal script is invalid')

    k, r = get_known_k_r()
    order = ecdsa.SECP256k1.order
    mhash = ecdsa.util.string_to_number(hashlib.sha256(b'\x01').digest())
    r_inverse = ecdsa.numbertheory.inverse_mod(r, order)

    for s in (-sig_s, sig_s):
        secret_exponent = (((s*k - mhash) % order) * r_inverse) % order

        recovered_key = CKey.from_secret_bytes(
            ecdsa.util.number_to_string(secret_exponent, order))

        if recovered_key.pub == key_to_reveal_pub:
            break
    else:
        die('Key recovery failed. Should not happen - the sig was already '
            'verified when transaction was accepted into mempool. '
            'Must be a bug.')

    say('recovered key pubkey: {}'.format(b2x(recovered_key.pub)))
    contract_key = CKey.sub(recovered_key, blinding_key)
    say('recovered unblined key pubkey: {}'.format(b2x(contract_key.pub)))
    combined_btc_spend_key = CKey.add(contract_key, alice_btc_key)

    say('Successfully recovered the key. Can now spend Bitcoin from {}'
        .format(btc_contract_addr))

    with ChainParams(bitcoin_chain_name):
        dst_addr = CCoinAddress(btc_rpc.getnewaddress())
        btc_claim_tx = create_btc_spend_tx(
            dst_addr, btc_txid, btc_vout_n, btc_contract,
            spend_key=combined_btc_spend_key)

    say('Sending my Bitcoin-claim transaction')
    btc_claim_txid = btc_rpc.sendrawtransaction(b2x(btc_claim_tx.serialize()))

    wait_confirm(say, 'Bitcoin', btc_claim_txid, die, btc_rpc, num_confirms=3)

    say('Got my Bitcoin. Swap successful!')


def bob(say, recv, send, die, btc_rpc, elt_rpc):
    """A function that implements the logic
    of the Bitcoin-side participant
    of confidential cross-chain atomic swap"""

    global last_wish_func

    # Default chain for Bob will be Bitcoin
    # To handle bitcoin-related objects, either
    # `with ChainParams(elements_chain_name):` have to be used, or
    # concrete classes, like CElementsAddress, CElementsTransaction, etc.
    select_chain_params(bitcoin_chain_name)

    say('Waiting for blinding key from Alice')
    alice_btc_pub_raw, alice_elt_exit_pub_raw = recv('pubkeys')

    blinding_key = CKey.from_secret_bytes(recv('blinding_key'))
    say("Pubkey for blinding key: {}".format(b2x(blinding_key.pub)))

    # Let's create the key that would lock the coins on Bitcoin side
    contract_key = CKey.from_secret_bytes(os.urandom(32))
    # And the key for Elements side
    bob_elt_spend_key = CKey.from_secret_bytes(os.urandom(32))
    # And the key for 'timeout' case on btc side
    bob_btc_exit_key = CKey.from_secret_bytes(os.urandom(32))

    key_to_reveal_pub = CPubKey.add(contract_key.pub, blinding_key.pub)
    say("The pubkey of the combined key to be revealed: {}"
        .format(b2x(key_to_reveal_pub)))

    say('Sending my pubkeys to Alice')
    send('pubkeys', (contract_key.pub, bob_elt_spend_key.pub,
                     bob_btc_exit_key.pub))

    combined_btc_spend_pubkey = CPubKey.add(contract_key.pub,
                                            CPubKey(alice_btc_pub_raw))

    say('combined_btc_spend_pubkey: {}'.format(b2x(combined_btc_spend_pubkey)))
    btc_contract = make_btc_contract(combined_btc_spend_pubkey,
                                     bob_btc_exit_key.pub)

    btc_contract_addr = P2WSHCoinAddress.from_redeemScript(btc_contract)

    say("Created Bitcoin-side swap contract, size: {}"
        .format(len(btc_contract)))
    say("Contract address: {}".format(btc_contract_addr))

    say('Sending {} to {}'.format(pre_agreed_amount, btc_contract_addr))
    btc_txid = btc_rpc.sendtoaddress(str(btc_contract_addr), pre_agreed_amount)

    def bob_last_wish_func():
        try_reclaim_btc(say, btc_rpc, btc_txid, btc_contract, bob_btc_exit_key,
                        die)

    last_wish_func = bob_last_wish_func

    wait_confirm(say, 'Bitcoin', btc_txid, die, btc_rpc, num_confirms=6)

    send('btc_txid', btc_txid)
    elt_txid = recv('elt_txid')

    elt_contract = make_elt_cntract(
        key_to_reveal_pub, bob_elt_spend_key.pub, alice_elt_exit_pub_raw)

    with ChainParams(elements_chain_name):
        elt_contract_addr = P2SHCoinAddress.from_redeemScript(elt_contract)

    say('Got Elements contract address from Alice: {}'
        .format(elt_contract_addr))
    say('Looking for this address in transaction {} in Elements'
        .format(elt_txid))

    tx_json = elt_rpc.getrawtransaction(elt_txid, 1)

    if tx_json['confirmations'] < 2:
        die('Transaction does not have enough confirmations')

    elt_commit_tx = CElementsTransaction.deserialize(x(tx_json['hex']))

    vout_n, unblind_result = find_and_unblind_vout(
        say, elt_commit_tx, elt_contract_addr, blinding_key, die)

    if unblind_result.amount != coins_to_satoshi(pre_agreed_amount):
        die('the amount {} found at the output in the offered transaction '
            'does not match the expected amount {}'
            .format(satoshi_to_coins(unblind_result.amount),
                    pre_agreed_amount))

    say('The asset and amount match expected values. lets spend it.')

    with ChainParams(elements_chain_name):
        dst_addr = CCoinAddress(elt_rpc.getnewaddress())
        assert isinstance(dst_addr, CCoinConfidentialAddress)

        say('I will claim my Elements-BTC to {}'.format(dst_addr))

        elt_claim_tx = create_elt_spend_tx(
            dst_addr, elt_txid, vout_n, elt_contract, die,
            spend_key=bob_elt_spend_key,
            contract_key=contract_key, blinding_key=blinding_key,
            blinding_factor=unblind_result.blinding_factor,
            asset_blinding_factor=unblind_result.asset_blinding_factor)

        # Cannot use VerifyScript for now,
        # because it does not support CHECKSIGFROMSTACK yet
        #
        # VerifyScript(tx.vin[0].scriptSig,
        #              elt_contract_addr.to_scriptPubKey(),
        #              tx, 0, amount=amount)

    say('Sending my spend-reveal transaction')
    sr_txid = elt_rpc.sendrawtransaction(b2x(elt_claim_tx.serialize()))

    wait_confirm(say, 'Elements', sr_txid, die, elt_rpc, num_confirms=2)

    say('Got my Elements-BTC. Swap successful (at least for me :-)')


# A function for a (non)-participant 'miner' process
def miner(say, recv, send, die, btc_rpc, elt_rpc):
    """A function that simulates a miner for regtest chains"""
    btc_mining_dst_addr = btc_rpc.getnewaddress()
    elt_mining_dst_addr = elt_rpc.getnewaddress()
    while True:
        btc_rpc.generatetoaddress(1, btc_mining_dst_addr)
        elt_rpc.generatetoaddress(1, elt_mining_dst_addr)
        time.sleep(2)  # One block each two seconds


# The auxiliary code that is required for Alice and Bob to function

def make_elt_cntract(reveal_key_pubkey, buyer_pubkey, seller_pubkey):

    _, r = get_known_k_r()
    r = ecdsa.util.number_to_string(r, ecdsa.SECP256k1.order).lstrip(b'\x00')

    # Note: There are other ways to force the counterparty to disclose
    # the key, some of them work even without CHECKSIGFROMSTACK. See:
    # https://bitcoin.stackexchange.com/questions/85936/bitcoin-scripts-that-force-disclosure-of-the-private-key
    # Since this is just for demostration purposes, I will use
    # this version, even if much smaller scripts are possible.

    return CElementsScript([
        OP_IF,
                       # At the start (after TRUE was consumed by IF):
                       # sig_prefix sig_suffix buyer_sig
            r,         # sig_r sig_prefix sig_suffix buyer_sig
            OP_CAT,    # sig_prefix+sig_r sig_suffix buyer_sig
            OP_SWAP,   # sig_suffix sig_prefix+sig_r buyer_sig
            OP_CAT,    # sig buyer_sig
            1,         # msg sig buyer_sig
            reveal_key_pubkey,
                       # rpub msg sig buyer_sig
            OP_CHECKSIGFROMSTACKVERIFY,
                       # buyer_sig
            buyer_pubkey,
                       # buyer_pubkey buyer_sig
        OP_ELSE,
            elements_contract_timeout, OP_CHECKSEQUENCEVERIFY,
            OP_DROP,
            seller_pubkey,
        OP_ENDIF,
        OP_CHECKSIG
    ]) # noqa: formatting


def make_btc_contract(buyer_combined_pubkey, seller_pubkey):
    return CBitcoinScript([
        OP_IF,
            buyer_combined_pubkey,
        OP_ELSE,
            bitcoin_contract_timeout, OP_CHECKSEQUENCEVERIFY, OP_DROP,
            seller_pubkey,
        OP_ENDIF,
        OP_CHECKSIG
    ]) # noqa: formatting


def find_and_unblind_vout(say, tx, elt_contract_addr, blinding_key, die):
    for vout_n, vout in enumerate(tx.vout):
        if vout.scriptPubKey == elt_contract_addr.to_scriptPubKey():
            say("Found the address at output {}".format(vout_n))
            unblind_result = vout.unblind_confidential_pair(
                blinding_key, tx.wit.vtxoutwit[vout_n].rangeproof)
            if unblind_result.error:
                die('cannot unblind the output: {}'
                    .format(unblind_result.error))
            if unblind_result.asset.to_hex() != bitcoin_asset.to_hex():
                die('output has wrong asset: expected {}, got {}'
                    .format(bitcoin_asset.to_hex(),
                            unblind_result.asset.to_hex()))
            break
    else:
        die('Did not find contract address in transaction')

    return vout_n, unblind_result


def try_reclaim_btc(say, btc_rpc, txid, btc_contract, key, die):

    ensure_rpc_connected(say, btc_rpc)

    # we won't return from this function, so we can just
    # set the chain with select_chain_params
    select_chain_params(bitcoin_chain_name)

    def custom_die(msg):
        say(msg)
        die('Failed to reclaim my Bitcoin')

    from_addr = P2WSHCoinAddress.from_redeemScript(btc_contract)

    say('Will try to reclaim my bitcoin from {}'.format(from_addr))

    tx_json = btc_rpc.getrawtransaction(txid, 1)
    confirmations = int(tx_json['confirmations'])

    while confirmations < bitcoin_contract_timeout:
        tx_json = btc_rpc.getrawtransaction(txid, 1)
        confirmations = int(tx_json['confirmations'])

    for vout in tx_json['vout']:
        if 'scriptPubKey' in vout:
            if str(from_addr) in vout['scriptPubKey']['addresses']:
                vout_n = int(vout['n'])
                say('({} at UTXO {}:{})'.format(vout['value'], txid, vout_n))
                break
    else:
        custom_die('Cannot find {} in outputs of tx {} - this must be a bug.'
                   .format(from_addr, txid))

    # We should not use CBitcoinAddress directly here, because we might be
    # in regtest or testnet, and it is treated as different chain.
    # CBitcoinAddress will not recognize regtest address, you would need
    # to use CBitcoinTestnetAddress/CBitcoinRegtestAddress.
    # CCoinAddress is the correct abstraction to use.
    dst_addr = CCoinAddress(btc_rpc.getnewaddress())

    say('Will reclaim my Bitcoin to {}'.format(dst_addr))
    reclaim_tx = create_btc_spend_tx(dst_addr, txid, vout_n, btc_contract,
                                     spend_key=key, branch_condition=False)

    say('Sending my Bitcoin-reclaim transaction')
    new_txid = btc_rpc.sendrawtransaction(b2x(reclaim_tx.serialize()))

    wait_confirm(say, 'Bitcoin', new_txid, custom_die, btc_rpc, num_confirms=3)

    say('Reclaimed my Bitcoin. Swap failed.')


def try_reclaim_elt(say, elt_rpc, txid, elt_contract, key, blinding_key, die):

    ensure_rpc_connected(say, elt_rpc)

    # we won't return from this function, so we can just
    # set the chain with select_chain_params
    select_chain_params(elements_chain_name)

    from_addr = P2SHCoinAddress.from_redeemScript(elt_contract)

    say('Will try to reclaim my Elements bitcoin asset from {}'
        .format(from_addr))

    tx_json = elt_rpc.getrawtransaction(txid, 1)
    confirmations = int(tx_json['confirmations'])

    while confirmations < elements_contract_timeout:
        tx_json = elt_rpc.getrawtransaction(txid, 1)
        confirmations = int(tx_json['confirmations'])

    commit_tx = CElementsTransaction.deserialize(x(tx_json['hex']))

    vout_n, unblind_result = find_and_unblind_vout(
        say, commit_tx, from_addr, blinding_key, die)

    dst_addr = CElementsAddress(elt_rpc.getnewaddress())

    say('Will reclaim my Elements asset to {}'.format(dst_addr))
    reclaim_tx = create_elt_spend_tx(
        dst_addr, txid, vout_n, elt_contract, die,
        spend_key=key,
        blinding_factor=unblind_result.blinding_factor,
        asset_blinding_factor=unblind_result.asset_blinding_factor,
        branch_condition=False)

    say('Sending my Elements-reclaim transaction')
    new_txid = elt_rpc.sendrawtransaction(b2x(reclaim_tx.serialize()))

    def custom_die(msg):
        say(msg)
        die('Failed to reclaim by Elemets asset')

    wait_confirm(say, 'Elements', new_txid, custom_die, elt_rpc,
                 num_confirms=3)

    say('Reclaimed my Elements asset. Swap failed.')


def create_btc_spend_tx(dst_addr, txid, vout_n, btc_contract,
                        spend_key=None, branch_condition=True):

    # In real application, the fees should not be static, of course
    out_amount = (coins_to_satoshi(pre_agreed_amount)
                  - coins_to_satoshi(fixed_fee_amount))

    tx = CMutableTransaction(
        vin=[CTxIn(prevout=COutPoint(hash=lx(txid), n=vout_n))],
        vout=[CTxOut(nValue=out_amount,
                     scriptPubKey=dst_addr.to_scriptPubKey())])

    if branch_condition is True:
        cond = b'\x01'
    else:
        tx.vin[0].nSequence = bitcoin_contract_timeout
        cond = b''

    in_amount = coins_to_satoshi(pre_agreed_amount)
    # We used P2WSHCoinAddress to create the address that we sent bitcoin to,
    # so we know that we need to use SIGVERSION_WITNESS_V0
    sighash = btc_contract.sighash(tx, 0, SIGHASH_ALL,
                                   amount=in_amount,
                                   sigversion=SIGVERSION_WITNESS_V0)

    spend_sig = spend_key.sign(sighash) + bytes([SIGHASH_ALL])

    # This is script witness, not script. The condition for OP_IF
    # in our script is directly encoded as data in the witness.
    # We cannot use OP_TRUE/OP_FALSE here. We use DATA guard is to ensure that.
    witness = CScriptWitness([spend_sig, DATA(cond), btc_contract])

    # empty scriptSig, because segwit
    tx.vin[0].scriptSig = CBitcoinScript([])
    # all data to check the spend conditions is in the witness
    tx.wit.vtxinwit[0] = CTxInWitness(witness)

    # Cannot use VerifyScript for now,
    # because it does not support CHECKSEQUENCEVERIFY yet
    #
    # from_addr = P2WSHBitcoinAddress.from_redeemScript(btc_contract)
    # VerifyScript(tx.vin[0].scriptSig, from_addr.to_scriptPubKey(),
    #              tx, 0, amount=in_amount)

    return tx


def create_elt_spend_tx(dst_addr, txid, vout_n, elt_contract, die,
                        spend_key=None, contract_key=None, blinding_key=None,
                        blinding_factor=None, asset_blinding_factor=None,
                        branch_condition=True):

    fee_satoshi = coins_to_satoshi(fixed_fee_amount)
    out_amount = coins_to_satoshi(pre_agreed_amount) - fee_satoshi

    # Single blinded output is not allowed, so we add
    # dummy OP_RETURN output, and we need dummy pubkey for it
    dummy_key = CKey.from_secret_bytes(os.urandom(32))

    tx = CMutableTransaction(
        vin=[CTxIn(prevout=COutPoint(hash=lx(txid), n=vout_n))],
        vout=[CTxOut(nValue=CConfidentialValue(out_amount),
                     nAsset=CConfidentialAsset(bitcoin_asset),
                     scriptPubKey=dst_addr.to_scriptPubKey(),
                     nNonce=CConfidentialNonce(dst_addr.blinding_pubkey)),
              CTxOut(nValue=CConfidentialValue(0),
                     nAsset=CConfidentialAsset(bitcoin_asset),
                     nNonce=CConfidentialNonce(dummy_key.pub),
                     scriptPubKey=CElementsScript([OP_RETURN])),
              CTxOut(nValue=CConfidentialValue(fee_satoshi),
                     nAsset=CConfidentialAsset(bitcoin_asset))])

    output_pubkeys = [dst_addr.blinding_pubkey, dummy_key.pub]

    in_amount = coins_to_satoshi(pre_agreed_amount)

    input_descriptors = [
        BlindingInputDescriptor(
            asset=bitcoin_asset,
            amount=in_amount,
            blinding_factor=blinding_factor,
            asset_blinding_factor=asset_blinding_factor)
    ]

    blind_result = tx.blind(
        input_descriptors=input_descriptors,
        output_pubkeys=output_pubkeys)

    # The blinding must succeed!
    if blind_result.error:
        die('blind failed: {}'.format(blind_result.error))

    if branch_condition is False:
        # Must set nSequence before we calculate signature hash,
        # because it is included in it
        tx.vin[0].nSequence = elements_contract_timeout

    # We used P2SHCoinAddress to create the address that
    # we sent Elements-BTC to, so we know that we need
    # to use SIGVERSION_BASE

    sighash = elt_contract.sighash(tx, 0, SIGHASH_ALL,
                                   amount=CConfidentialValue(in_amount),
                                   sigversion=SIGVERSION_BASE)

    spend_sig = spend_key.sign(sighash) + bytes([SIGHASH_ALL])

    if branch_condition is True:
        prepare_elt_spend_reveal_branch(tx, elt_contract, spend_sig,
                                        contract_key, blinding_key)
    else:
        tx.vin[0].scriptSig = CElementsScript([
            spend_sig,
            OP_FALSE,
            elt_contract
        ])

    return tx


def prepare_elt_spend_reveal_branch(tx, elt_contract, spend_sig,
                                    contract_key, blinding_key):

    key_to_reveal = CKey.add(contract_key, blinding_key)

    rkey = ecdsa.keys.SigningKey.from_string(
        key_to_reveal.secret_bytes, curve=ecdsa.SECP256k1)

    k, r = get_known_k_r()
    r = ecdsa.util.number_to_string(r, ecdsa.SECP256k1.order).lstrip(b'\x00')

    reveal_sig = rkey.sign_digest(hashlib.sha256(b'\x01').digest(), k=k,
                                  sigencode=ecdsa.util.sigencode_der_canonize)

    # For reference: signature serialization code from secp256k1 library
    #
    # sig[0] = 0x30;
    # sig[1] = 4 + lenS + lenR;
    # sig[2] = 0x02;
    # sig[3] = lenR;
    # memcpy(sig+4, rp, lenR);
    # sig[4+lenR] = 0x02;
    # sig[5+lenR] = lenS;
    # memcpy(sig+lenR+6, sp, lenS);

    assert reveal_sig[3] == len(r)
    assert reveal_sig[4:4+(len(r))] == r

    sig_prefix = reveal_sig[:4]
    sig_suffix = reveal_sig[4+len(r):]

    # Expected stack after OP_IF branch taken:
    # sig_r sig1_pfx sig1_sfx sig2_pfx sig2_sfx spend_sig
    tx.vin[0].scriptSig = CElementsScript([
        spend_sig,
        sig_suffix, sig_prefix,
        OP_TRUE,
        elt_contract
    ])


def get_known_k_r():
    # Known k value that would give smallest
    # x coordinate for R (21 byte length). See:
    # https://crypto.stackexchange.com/questions/60420/what-does-the-special-form-of-the-base-point-of-secp256k1-allow
    # https://bitcointalk.org/index.php?topic=289795.msg3183975#msg3183975
    k = (ecdsa.SECP256k1.order + 1) // 2
    r = ecdsa.SECP256k1.generator * k

    return k, r.x()


def main():
    """The main function prepares everyting for two participant processes
    to operate and communicate with each other, and starts them"""

    global console_lock
    global bitcoin_asset

    if len(sys.argv) != 4:
        sys.stderr.write(
            "usage: {} <bitcoin-daemon-dir> <elements-daemon-dir> "
            "<bitcoin_asset_hex>\n"
            .format(sys.argv[0]))
        sys.exit(-1)

    bitcoin_config_path = os.path.join(sys.argv[1], 'bitcoin.conf')
    if not os.path.isfile(bitcoin_config_path):
        sys.stderr.write(
            'config file {} not found or is not a regular file'
            .format(bitcoin_config_path))
        sys.exit(-1)

    elements_config_path = os.path.join(sys.argv[2], 'elements.conf')
    if not os.path.isfile(elements_config_path):
        sys.stderr.write(
            'config file {} not found or is not a regular file'
            .format(elements_config_path))
        sys.exit(-1)

    try:
        bitcoin_asset = CAsset(lx(sys.argv[3]))
    except ValueError as e:
        sys.stderr.write('specified fee asset is not valid: {}\n'.format(e))
        sys.exit(-1)
    # Initialize console lock
    console_lock = Lock()

    # Create a pipe for processes to communicate
    pipe1, pipe2 = Pipe(duplex=True)

    # Create process to run 'alice' participant function
    # and pass it one end of a pipe, and path to config file
    # for Elements daemon
    p1 = Process(target=participant, name='alice',
                 args=(alice, 'Alice', pipe1,
                       bitcoin_config_path, elements_config_path))

    # Create process to run 'bob' participant function
    # and pass it one end of a pipe, and path to config file
    # for Bitcoin daemon
    p2 = Process(target=participant, name='bob',
                 args=(bob, '  Bob', pipe2,
                       bitcoin_config_path, elements_config_path))

    # Create process to run 'miner' (non)-participant function
    # and pass it one end of a pipe, and path to config file
    # for Bitcoin daemon
    p3 = Process(target=participant, name='miner',
                 args=(miner, 'Miner', None,
                       bitcoin_config_path, elements_config_path))

    # Start both processes
    p1.start()
    p2.start()
    p3.start()

    # The childs are on their own now. We just wait for them to finish.
    try:
        p1.join()
        p2.join()
    except KeyboardInterrupt:
        print()
        print("=============================================================")
        print("Interrupted from keyboard, terminating participant processes.")
        print("-------------------------------------------------------------")
        for p in (p1, p2):
            if p.is_alive():
                print('terminating', p.name)
                p.terminate()
            else:
                print(p.name, 'is not alive')
            p.join()
        print('Exiting.')
        print("=============================================================")

    print('Terminating the miner process')
    p3.terminate()
    p3.join()


def participant(func, name, pipe, bitcoin_config_path, elements_config_path):
    """Prepares environment for participants, run their functions,
    and handles the errors they did not bother to hanlde"""

    def say(msg): participant_says(name, msg)

    # Custom exception class to distinguish a case when
    # participant calss die() from other exceptions
    class ProtocolFailure(Exception):
        ...

    def do_last_wish(msg):
        global last_wish_func
        lwf = last_wish_func
        if lwf:
            say("Going to die because '{}', "
                "but I still have something to do before that."
                .format(msg))
            last_wish_func = None
            lwf()

    def die(msg, peacefully=False):
        do_last_wish(msg)
        if peacefully:
            sys.exit(-1)
        raise ProtocolFailure(msg)

    def recv(expected_type, timeout=60):
        if not pipe.poll(timeout):
            die('No messages received in {} seconds'.format(timeout))
        msg = pipe.recv()

        if msg[0] == 'bye!':
            msg = 'Communication finished unexpectedly'
            say(msg + ', exiting.')
            do_last_wish(msg)
            sys.exit(-1)

        if msg[0] != expected_type:
            die("unexpected message type '{}', expected '{}'"
                .format(msg[0], expected_type))

        return msg[1]

    def send(msg_type, data=None): pipe.send([msg_type, data])

    # Ignore keyboard interrupt, parent process handles it.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        # Connect to Elements or Bitcoin RPC with specified path
        # Do it with context params switch, so that appropriate values
        # from config files will be used (there may be regtest.port=N, etc)
        with ChainParams(bitcoin_chain_name):
            btc_rpc = connect_rpc(say, bitcoin_config_path)
        with ChainParams(elements_chain_name):
            elt_rpc = connect_rpc(say, elements_config_path)
        # Execute participant's function
        func(say, recv, send, die, btc_rpc, elt_rpc)
    except Exception as e:
        say('FAIL with {}: {}'.format(type(e).__name__, e))
        say("Traceback:")
        print("="*80)
        traceback.print_tb(sys.exc_info()[-1])
        print("="*80)
        do_last_wish(e.__class__.__name__)
        send('bye!')
        sys.exit(-1)


def participant_says(name, msg):
    """A helper function to coordinate
    console message output between processes"""

    color = ansi_colors.get(name.strip().lower(), '')
    console_lock.acquire()
    try:
        print("{}{}: {}{}".format(color, name, msg,
                                  end_color if color else ''))
    finally:
        console_lock.release()


def connect_rpc(say, config_path):
    """Connect to Elements daemon RPC and return RPCCaller interface"""

    say('Connecting to Elements daemon RPC interface, using config in {}'
        .format(config_path))

    return RPCCaller(conf_file=config_path)


def ensure_rpc_connected(say, rpc):
    try:
        rpc.ping()
    except ConnectionError as e:
        say('rpc connection broke: {}'.format(e))
        say('trying to reconnect')
        rpc.connect()


def wait_spend_reveal_transaction(say, contract_txid, die, elt_rpc):
    current_blockhash = None
    next_blockhash = None
    while True:
        tx = elt_rpc.getrawtransaction(contract_txid, 1)
        if tx.get('confirmations', 0) > elements_contract_timeout:
            die('Waiting for too long, time to reclaim my funds',
                peacefully=True)

        if current_blockhash is None:
            # First time, or our transaction has 'lost' the block
            # because of reorg. Note that in real application,
            # there's also a possibility of transaction not only
            # being 'unconfirmed', but also may fall out of mempool,
            # and you would need to re-send it.
            # We do not do it here to keep the example relatively simple.
            current_blockhash = tx.get('blockhash')
            time.sleep(1)
            continue

        try:
            blk = elt_rpc.getblock(current_blockhash)
        except JSONRPCError as e:
            if e.error['code'] == -5:
                # block not found
                say('our transaction was in block {}, but now that '
                    'block is gone, will look for new one')
                current_blockhash = None
                continue

        for txid in blk['tx']:
            tx = elt_rpc.getrawtransaction(txid, 1)
            for vin in tx['vin']:
                if vin.get('txid') == contract_txid:
                    return txid

        next_blockhash = blk.get('nextblockhash')

        if next_blockhash is None:
            # Wait for next block to arrive
            time.sleep(1)
        else:
            # There is next block alredy, check it
            current_blockhash = next_blockhash


def wait_confirm(say, net_name, txid, die, rpc, num_confirms=1):
    """Wait for particular transaction to be confirmed.
    generate test blocks if it is in mempool, but not confirmed.
    raise Exception if not confirmed in 60 seconds"""

    say('Waiting for {} txid {} to confim'.format(net_name, txid))
    for _ in range(60):
        try:
            confirms = rpc.getrawtransaction(txid, 1).get('confirmations', 0)
            if confirms >= num_confirms:
                return True
        except JSONRPCError as e:
            if e.error['code'] == -5:
                # Not yet in mempool, wait
                pass
        time.sleep(1)

    # the caller may not want to die, and pass `lambda: False` instead
    return die('timed out waiting for confirmation')


if __name__ == '__main__':
    main()
