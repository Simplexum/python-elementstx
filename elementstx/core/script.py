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

import struct
from io import BytesIO

from bitcointx.util import no_bool_use_as_property
from bitcointx.core import Hash
from bitcointx.core.script import (
    ScriptCoinClassDispatcher, ScriptCoinClass,
    CScript, CScriptOp,
    SIGVERSION_BASE, SIGVERSION_WITNESS_V0,
    CScriptInvalidError,
    RawBitcoinSignatureHash,
    OP_RETURN,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
)
from bitcointx.core.serialize import BytesSerializer
import elementstx.core

# We do not register these extra opcodes in script.OPCODE_NAMES
# and script.OPCODE_BY_NAME. If we do so, we will pollute these
# bitcoin-specific tables with Elements opcodes. Proper way would be
# to have CBitcoinScriptOp and CElementsScriptOp, but
# this is too heavy for this small issue. These opcodes are useable as-is,
# the only proble is that they will be shown as UNKNOWN for repr(script).
OP_DETERMINISTICRANDOM = CScriptOp(0xc1)
OP_CHECKSIGFROMSTACK = CScriptOp(0xc1)
OP_CHECKSIGFROMSTACKVERIFY = CScriptOp(0xc2)


class ScriptElementsClassDispatcher(ScriptCoinClassDispatcher):
    ...


class ScriptElementsClass(ScriptCoinClass,
                          metaclass=ScriptElementsClassDispatcher):
    ...


def RawElementsSignatureHash(script, txTo, inIdx, hashtype, amount=0,
                             sigversion=SIGVERSION_BASE):
    """Consensus-correct SignatureHash

    Returns (hash, err) to precisely match the consensus-critical behavior of
    the SIGHASH_SINGLE bug. (inIdx is *not* checked for validity)

    If you're just writing wallet software you probably want SignatureHash()
    instead.
    """
    assert sigversion in (SIGVERSION_BASE, SIGVERSION_WITNESS_V0)

    if sigversion == SIGVERSION_BASE:
        # revert to standard bitcoin signature hash
        return RawBitcoinSignatureHash(script, txTo, inIdx, hashtype,
                                       amount=amount, sigversion=sigversion)

    assert isinstance(amount, elementstx.core.CConfidentialValue),\
        "amount must actually be a confidential commitment"

    hashPrevouts = b'\x00'*32
    hashSequence = b'\x00'*32
    hashIssuance = b'\x00'*32
    hashOutputs  = b'\x00'*32  # noqa

    if not (hashtype & SIGHASH_ANYONECANPAY):
        serialize_prevouts = bytes()
        serialize_issuance = bytes()
        for vin in txTo.vin:
            serialize_prevouts += vin.prevout.serialize()
            if vin.assetIssuance.is_null():
                serialize_issuance += b'\x00'
            else:
                f = BytesIO()
                BytesSerializer.stream_serialize(vin.assetIssuance, f)
                serialize_issuance += f.getbuffer()
        hashPrevouts = Hash(serialize_prevouts)
        hashIssuance = Hash(serialize_issuance)

    if (not (hashtype & SIGHASH_ANYONECANPAY) and (hashtype & 0x1f) != SIGHASH_SINGLE and (hashtype & 0x1f) != SIGHASH_NONE):
        serialize_sequence = bytes()
        for i in txTo.vin:
            serialize_sequence += struct.pack("<I", i.nSequence)
        hashSequence = Hash(serialize_sequence)

    if ((hashtype & 0x1f) != SIGHASH_SINGLE and (hashtype & 0x1f) != SIGHASH_NONE):
        serialize_outputs = bytes()
        for o in txTo.vout:
            serialize_outputs += o.serialize()
        hashOutputs = Hash(serialize_outputs)
    elif ((hashtype & 0x1f) == SIGHASH_SINGLE and inIdx < len(txTo.vout)):
        serialize_outputs = txTo.vout[inIdx].serialize()
        hashOutputs = Hash(serialize_outputs)

    f = BytesIO()
    f.write(struct.pack("<i", txTo.nVersion))
    f.write(hashPrevouts)
    f.write(hashSequence)
    f.write(hashIssuance)
    txTo.vin[inIdx].prevout.stream_serialize(f)
    BytesSerializer.stream_serialize(script, f)
    f.write(amount.commitment)
    f.write(struct.pack("<I", txTo.vin[inIdx].nSequence))
    if not txTo.vin[inIdx].assetIssuance.is_null():
        BytesSerializer.stream_serialize(txTo.vin[inIdx].assetIssuance, f)
    f.write(hashOutputs)
    f.write(struct.pack("<i", txTo.nLockTime))
    f.write(struct.pack("<i", hashtype))

    hash = Hash(f.getvalue())

    return (hash, None)


class CElementsScript(CScript, ScriptElementsClass):

    def derive_blinding_key(self, blinding_derivation_key):
        return elementstx.core.derive_blinding_key(
            blinding_derivation_key, self)

    @no_bool_use_as_property
    def is_unspendable(self):
        if len(self) == 0:
            return True
        return super(CElementsScript, self).is_unspendable()

    def raw_sighash(self, txTo, inIdx, hashtype, amount=0, sigversion=SIGVERSION_BASE):
        """Consensus-correct SignatureHash

        Returns (hash, err) to precisely match the consensus-critical behavior of
        the SIGHASH_SINGLE bug. (inIdx is *not* checked for validity)

        If you're just writing wallet software you probably want sighash() method instead."""
        return RawElementsSignatureHash(self, txTo, inIdx, hashtype,
                                        amount=amount, sigversion=sigversion)

    def get_pegout_data(self):
        try:
            op_iter = self.raw_iter()
            op, _, _ = next(op_iter)
            if op != OP_RETURN:
                return None

            op, op_data, _ = next(op_iter)
            if len(op_data) != 32:
                return None

            genesis_hash = op_data

            op, op_data, _ = next(op_iter)

            if len(op_data) == 0:
                return False

            pegout_scriptpubkey = self.__class__(op_data)

            # The code in reference client does not check if there
            # is more data after pegout_scriptpubkey.

        except CScriptInvalidError:
            return None
        except StopIteration:
            return None

        return (genesis_hash, pegout_scriptpubkey)

    @no_bool_use_as_property
    def is_pegout(self):
        return self.get_pegout_data() is not None


__all__ = (
    'CElementsScript',
    'RawElementsSignatureHash',
)
