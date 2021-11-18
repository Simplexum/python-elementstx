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

# pylama:ignore=E501,C901

import struct
import hashlib
from io import BytesIO
from typing import Optional, Tuple, Sequence

from bitcointx.util import no_bool_use_as_property, ensure_isinstance
from bitcointx.core import Hash
from bitcointx.core.key import CKey, CKeyBase
from bitcointx.core.script import (
    ScriptCoinClassDispatcher, ScriptCoinClass,
    CScript, CScriptOp,
    SIGVERSION_BASE, SIGVERSION_WITNESS_V0,
    SIGVERSION_TAPROOT, SIGVERSION_TAPSCRIPT,
    CScriptInvalidError,
    RawBitcoinSignatureHash,
    OP_RETURN,
    SIGHASH_NONE,
    SIGHASH_ALL,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
    SIGHASH_Type, SIGVERSION_Type,
    TaprootScriptTree
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

OP_SUBSTR_LAZY = CScriptOp(0xc3)

# Elements: Tapscript (Streaming sha2 opcodes)
OP_SHA256INITIALIZE = CScriptOp(0xc4)
OP_SHA256UPDATE = CScriptOp(0xc5)
OP_SHA256FINALIZE = CScriptOp(0xc6)

# Introspection opcodes

# inputs
OP_INSPECTINPUTOUTPOINT = CScriptOp(0xc7)
OP_INSPECTINPUTASSET = CScriptOp(0xc8)
OP_INSPECTINPUTVALUE = CScriptOp(0xc9)
OP_INSPECTINPUTSCRIPTPUBKEY = CScriptOp(0xca)
OP_INSPECTINPUTSEQUENCE = CScriptOp(0xcb)
OP_INSPECTINPUTISSUANCE = CScriptOp(0xcc)

# current index
OP_PUSHCURRENTINPUTINDEX = CScriptOp(0xcd)

# outputs
OP_INSPECTOUTPUTASSET = CScriptOp(0xce)
OP_INSPECTOUTPUTVALUE = CScriptOp(0xcf)
OP_INSPECTOUTPUTNONCE = CScriptOp(0xd0)
OP_INSPECTOUTPUTSCRIPTPUBKEY = CScriptOp(0xd1)

# transaction
OP_INSPECTVERSION = CScriptOp(0xd2)
OP_INSPECTLOCKTIME = CScriptOp(0xd3)
OP_INSPECTNUMINPUTS = CScriptOp(0xd4)
OP_INSPECTNUMOUTPUTS = CScriptOp(0xd5)
OP_TXWEIGHT = CScriptOp(0xd6)

# Arithmetic opcodes
OP_ADD64 = CScriptOp(0xd7)
OP_SUB64 = CScriptOp(0xd8)
OP_MUL64 = CScriptOp(0xd9)
OP_DIV64 = CScriptOp(0xda)
OP_NEG64 = CScriptOp(0xdb)
OP_LESSTHAN64 = CScriptOp(0xdc)
OP_LESSTHANOREQUAL64 = CScriptOp(0xdd)
OP_GREATERTHAN64 = CScriptOp(0xde)
OP_GREATERTHANOREQUAL64 = CScriptOp(0xdf)

# Conversion opcodes
OP_SCRIPTNUMTOLE64 = CScriptOp(0xe0)
OP_LE64TOSCRIPTNUM = CScriptOp(0xe1)
OP_LE32TOLE64 = CScriptOp(0xe2)

# Crypto opcodes
OP_ECMULSCALARVERIFY = CScriptOp(0xe3)
OP_TWEAKVERIFY = CScriptOp(0xe4)


class ScriptElementsClassDispatcher(ScriptCoinClassDispatcher):
    ...


class ScriptElementsClass(ScriptCoinClass,
                          metaclass=ScriptElementsClassDispatcher):
    ...


def RawElementsSignatureHash(
    script: CScript,
    txTo: 'elementstx.core.CElementsTransaction',
    inIdx: int,
    hashtype: SIGHASH_Type,
    amount: Optional['elementstx.core.CConfidentialValue'] = None,
    sigversion: SIGVERSION_Type = SIGVERSION_BASE
) -> Tuple[bytes, Optional[str]]:
    """Consensus-correct SignatureHash

    Returns (hash, err) to precisely match the consensus-critical behavior of
    the SIGHASH_SINGLE bug. (inIdx is *not* checked for validity)

    If you're just writing wallet software you probably want SignatureHash()
    instead.
    """
    if sigversion not in (SIGVERSION_BASE, SIGVERSION_WITNESS_V0):
        raise ValueError('unexpected sigversion')

    if sigversion == SIGVERSION_BASE:
        # revert to standard bitcoin signature hash
        # amount is not used in SIGVERSION_BASE sighash,
        # so we specify invalid value.
        return RawBitcoinSignatureHash(script, txTo, inIdx, hashtype,
                                       amount=-1, sigversion=sigversion)

    ensure_isinstance(amount, elementstx.core.CConfidentialValue, 'amount')
    assert isinstance(amount, elementstx.core.CConfidentialValue)

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
                serialize_issuance += vin.assetIssuance.serialize()
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
        txTo.vin[inIdx].assetIssuance.stream_serialize(f)
    f.write(hashOutputs)
    f.write(struct.pack("<i", txTo.nLockTime))
    f.write(struct.pack("<i", hashtype))

    hash = Hash(f.getvalue())

    return (hash, None)


def ElementsSignatureHashSchnorr(
    txTo: 'elementstx.core.CElementsTransaction',
    inIdx: int,
    spent_outputs: Sequence['elementstx.core.CElementsTxOut'],
    *,
    hashtype: Optional[SIGHASH_Type] = None,
    sigversion: SIGVERSION_Type = SIGVERSION_TAPROOT,
    tapleaf_hash: Optional[bytes] = None,
    codeseparator_pos: int = -1,
    annex_hash: Optional[bytes] = None,
    genesis_block_hash: bytes
) -> bytes:
    if inIdx < 0:
        raise ValueError('input index must not be negative')

    if inIdx >= len(txTo.vin):
        raise ValueError(f'inIdx {inIdx} out of range ({len(txTo.vin)})')

    if tapleaf_hash is not None:
        ensure_isinstance(tapleaf_hash, bytes, 'tapleaf_hash')
        if len(tapleaf_hash) != 32:
            raise ValueError('tapleaf_hash must be exactly 32 bytes long')

    if annex_hash is not None:
        ensure_isinstance(annex_hash, bytes, 'annex_hash')
        if len(annex_hash) != 32:
            raise ValueError('annex_hash must be exactly 32 bytes long')

    ensure_isinstance(genesis_block_hash, bytes, 'genesis_block_hash')
    if len(genesis_block_hash) != 32:
        raise ValueError('genesis_block_hash must be exactly 32 bytes long')

    if sigversion == SIGVERSION_TAPROOT:
        ext_flag = 0
    elif sigversion == SIGVERSION_TAPSCRIPT:
        ext_flag = 1
        # key_version is always 0 in Elements Core at the moment, representing
        # the current version of  32-byte public keys in the tapscript
        # signature opcode execution. An upgradable public key version
        # (with a size not 32-byte) may request a different key_version
        # with a new sigversion.
        key_version = 0
    else:
        raise ValueError('unsupported sigversion')

    if len(spent_outputs) != len(txTo.vin):
        raise ValueError(
            'number of spent_outputs is not equal to number of inputs')

    f = BytesIO()

    # No epoch in elements taphash
    # f.write(bytes([0]))

    # Hash type
    if hashtype is None:
        hashtype = SIGHASH_ALL
        hashtype_byte = b'\x00'
    else:
        ensure_isinstance(hashtype, SIGHASH_Type, 'hashtype')
        hashtype_byte = bytes([hashtype])

    input_type = hashtype.input_type
    output_type = hashtype.output_type

    # Transaction level data
    f.write(hashtype_byte)
    f.write(struct.pack("<i", txTo.nVersion))
    f.write(struct.pack("<I", txTo.nLockTime))

    def get_outpoint_flag(txin: 'elementstx.core.CElementsTxIn') -> bytes:
        opf = 0

        if not txin.assetIssuance.is_null():
            opf |= elementstx.core.OUTPOINT_ISSUANCE_FLAG

        if txin.is_pegin:
            opf |= elementstx.core.OUTPOINT_PEGIN_FLAG

        return bytes([opf >> 24])

    if input_type != SIGHASH_ANYONECANPAY:
        outpoints_flag_hashobj = hashlib.sha256()
        assets_amounts_hashobj = hashlib.sha256()
        scripts_hashobj = hashlib.sha256()
        prevouts_hashobj = hashlib.sha256()
        sequences_hashobj = hashlib.sha256()
        issuances_hashobj = hashlib.sha256()
        issuance_rangeproof_hashobj = hashlib.sha256()

        for sout in spent_outputs:
            assets_amounts_hashobj.update(sout.nAsset.serialize())
            assets_amounts_hashobj.update(sout.nValue.serialize())
            scripts_hashobj.update(BytesSerializer.serialize(sout.scriptPubKey))

        for inp_i, txin in enumerate(txTo.vin):
            outpoints_flag_hashobj.update(get_outpoint_flag(txin))
            prevouts_hashobj.update(txin.prevout.serialize())
            sequences_hashobj.update(struct.pack('<I', txin.nSequence))
            if txin.assetIssuance.is_null():
                issuances_hashobj.update(b'\x00')
            else:
                issuances_hashobj.update(txin.assetIssuance.serialize())

            inwit = txTo.wit.vtxinwit[inp_i]
            issuance_rangeproof_hashobj.update(
                BytesSerializer.serialize(inwit.issuanceAmountRangeproof))
            issuance_rangeproof_hashobj.update(
                BytesSerializer.serialize(inwit.inflationKeysRangeproof))

        f.write(outpoints_flag_hashobj.digest())
        f.write(prevouts_hashobj.digest())
        f.write(assets_amounts_hashobj.digest())
        # Why is nNonce not included in sighash? (both in ACP and non ACP case)
        #
        # Nonces are not serialized into utxo database. As a consequence, after restarting the node,
        # all nonces in the utxoset are cleared which results in a inconsistent view for nonces for
        # nodes that did not restart. See https://github.com/ElementsProject/elements/issues/1004 for details
        f.write(scripts_hashobj.digest())
        f.write(sequences_hashobj.digest())
        f.write(issuances_hashobj.digest())
        f.write(issuance_rangeproof_hashobj.digest())

    if output_type == SIGHASH_ALL:
        outputs_hashobj = hashlib.sha256()
        output_witnesses_hashobj = hashlib.sha256()

        for outp_i, txout in enumerate(txTo.vout):
            outputs_hashobj.update(txout.serialize())
            output_witnesses_hashobj.update(
                txTo.wit.vtxoutwit[outp_i].serialize())

        f.write(outputs_hashobj.digest())
        f.write(output_witnesses_hashobj.digest())

    spend_type = ext_flag << 1

    if annex_hash is not None:
        spend_type += 1  # The low bit indicates whether an annex is present

    f.write(bytes([spend_type]))

    if input_type == SIGHASH_ANYONECANPAY:
        f.write(get_outpoint_flag(txTo.vin[inIdx]))
        f.write(txTo.vin[inIdx].prevout.serialize())
        f.write(spent_outputs[inIdx].nAsset.serialize())
        f.write(spent_outputs[inIdx].nValue.serialize())
        f.write(spent_outputs[inIdx].scriptPubKey)
        f.write(struct.pack('<I', txTo.vin[inIdx].nSequence))
        if txTo.vin[inIdx].assetIssuance.is_null():
            f.write(b'\x00')
        else:
            f.write(txTo.vin[inIdx].assetIssuance.serialize())

            inwit = txTo.wit.vtxinwit[inIdx]
            f.write(
                hashlib.sha256(
                    inwit.issuanceAmountRangeproof
                    + inwit.inflationKeysRangeproof
                ).digest()
            )
    else:
        f.write(struct.pack('<I', inIdx))

    if annex_hash is not None:
        BytesSerializer.stream_serialize(annex_hash, f)

    if output_type == SIGHASH_SINGLE:
        outIdx = inIdx
        if outIdx > len(txTo.vout):
            raise ValueError(f'outIdx {outIdx} out of range ({len(txTo.vout)})')
        f.write(hashlib.sha256(txTo.vout[outIdx].serialize()).digest())
        f.write(hashlib.sha256(txTo.wit.vtxoutwit[outIdx].serialize()).digest())

    if sigversion == SIGVERSION_TAPSCRIPT:
        if tapleaf_hash is None:
            raise ValueError('tapleaf_hash must be specified for SIGVERSION_TAPSCRIPT')
        if codeseparator_pos is None:
            raise ValueError('codeseparator_pos must be specified for SIGVERSION_TAPSCRIPT')
        f.write(tapleaf_hash)
        f.write(bytes([key_version]))
        f.write(struct.pack("<i", codeseparator_pos))

    return elementstx.core.CoreElementsParams.tap_sighash_hasher(
        genesis_block_hash*2 + f.getvalue())


class CElementsScript(CScript, ScriptElementsClass):

    def derive_blinding_key(self, blinding_derivation_key: CKeyBase) -> CKey:
        return elementstx.core.derive_blinding_key(
            blinding_derivation_key, self)

    @no_bool_use_as_property
    def is_unspendable(self) -> bool:
        if len(self) == 0:
            return True
        return super(CElementsScript, self).is_unspendable()

    # The signature cannot be compatible with CScript's sighash,
    # because the amount is a confidential value, that cannot be
    # a subclass of int (the type of amount in CBitcoinScript)
    def sighash(self,  # type: ignore
                txTo: 'elementstx.core.CElementsTransaction', inIdx: int,
                hashtype: SIGHASH_Type,
                amount: Optional['elementstx.core.CConfidentialValue'] = None,
                sigversion: SIGVERSION_Type = SIGVERSION_BASE) -> bytes:

        hashtype = SIGHASH_Type(hashtype)

        (h, err) = self.raw_sighash(txTo, inIdx, hashtype, amount=amount,
                                    sigversion=sigversion)
        if err is not None:
            raise ValueError(err)
        return h

    # The signature cannot be compatible with CSript's raw_sighash,
    # because the amount is a confidential value, that cannot be
    # a subclass of int (the type of amount in CBitcoinScript)
    def raw_sighash(self,  # type: ignore
                    txTo: 'elementstx.core.CElementsTransaction',
                    inIdx: int,
                    hashtype: SIGHASH_Type,
                    amount: Optional['elementstx.core.CConfidentialValue'] = None,
                    sigversion: SIGVERSION_Type = SIGVERSION_BASE
                    ) -> Tuple[bytes, Optional[str]]:
        """Consensus-correct SignatureHash

        Returns (hash, err) to precisely match the consensus-critical behavior of
        the SIGHASH_SINGLE bug. (inIdx is *not* checked for validity)

        If you're just writing wallet software you probably want sighash() method instead."""
        return RawElementsSignatureHash(self, txTo, inIdx, hashtype,
                                        amount=amount, sigversion=sigversion)

    # The signature cannot be compatible with CSript's sighash_schnorr,
    # because txTo and spent_outputs are CElements-specific, and
    # mypy deems them incompatible with CScript's CTransaction and CTxOut,
    # for some reason (although they are subtypes of that classes)
    def sighash_schnorr(self,  # type: ignore
                        txTo: 'elementstx.core.CElementsTransaction',
                        inIdx: int,
                        spent_outputs: Sequence['elementstx.core.CElementsTxOut'],
                        *,
                        hashtype: Optional[SIGHASH_Type] = None,
                        codeseparator_pos: int = -1,
                        annex_hash: Optional[bytes] = None,
                        genesis_block_hash: bytes
                        ) -> bytes:

        # Only BIP342 tapscript signing is supported for now.
        leaf_version = elementstx.core.CoreElementsParams.TAPROOT_LEAF_TAPSCRIPT
        tapleaf_hash = elementstx.core.CoreElementsParams.tapleaf_hasher(
            bytes([leaf_version]) + BytesSerializer.serialize(self)
        )

        return ElementsSignatureHashSchnorr(
            txTo, inIdx, spent_outputs,
            hashtype=hashtype,
            sigversion=SIGVERSION_TAPSCRIPT,
            tapleaf_hash=tapleaf_hash,
            codeseparator_pos=codeseparator_pos,
            annex_hash=annex_hash,
            genesis_block_hash=genesis_block_hash)

    def get_pegout_data(self) -> Optional[Tuple[bytes, CScript]]:
        try:
            op_iter = self.raw_iter()
            op, _, _ = next(op_iter)
            if op != OP_RETURN:
                return None

            op, op_data, _ = next(op_iter)

            if op_data is None:
                return None

            if len(op_data) != 32:
                return None

            genesis_hash = op_data

            op, op_data, _ = next(op_iter)

            if op_data is None:
                return None

            if len(op_data) == 0:
                return None

            pegout_scriptpubkey = self.__class__(op_data)

            # The code in reference client does not check if there
            # is more data after pegout_scriptpubkey.

        except CScriptInvalidError:
            return None
        except StopIteration:
            return None

        return (genesis_hash, pegout_scriptpubkey)

    @no_bool_use_as_property
    def is_pegout(self) -> bool:
        return self.get_pegout_data() is not None


class TaprootElementsScriptTree(TaprootScriptTree, ScriptElementsClass):
    ...


__all__ = (
    'CElementsScript',
    'RawElementsSignatureHash',
    'ElementsSignatureHashSchnorr',
    'TaprootElementsScriptTree',
)
