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

from .version import __version__

import os
from typing import Optional

import elementstx.core
import elementstx.wallet
import elementstx.util

from bitcointx import ChainParamsBase


class ElementsParams(ChainParamsBase,
                     name=('elements', 'elements/elementsregtest')):
    RPC_PORT = 7041
    WALLET_DISPATCHER = elementstx.wallet.WalletElementsClassDispatcher

    def get_datadir_extra_name(self) -> str:
        name_parts = self.NAME.split('/')
        if len(name_parts) == 1:
            # Data dir for Elements is 'elementsregtest'
            return name_parts[0] + 'regtest'
        return name_parts[1]

    def get_network_id(self) -> str:
        return self.get_datadir_extra_name()


class ElementsLiquidV1Params(ElementsParams, name='elements/liquidv1'):
    RPC_PORT = 7042
    WALLET_DISPATCHER = elementstx.wallet.WalletElementsLiquidV1ClassDispatcher

    def get_datadir_extra_name(self) -> str:
        return self.NAME.split('/')[1]


def set_custom_secp256k1_path(path: str) -> None:
    """Set the custom path that will be used to load secp256k1 library
    by elementstx.core.secp256k1 module. For the calling of this
    function to have any effect, it has to be called before any
    function that uses secp256k1 handle is called"""

    if not os.path.isfile(path):
        raise ValueError('supplied path does not point to a file')

    elementstx.util._secp256k1_library_path = path


def get_custom_secp256k1_path() -> Optional[str]:
    """Return the path set earlier by set_custom_secp256k1_path().
    If custom path was not set, None is returned"""

    return elementstx.util._secp256k1_library_path


__all__ = (
    '__version__',
    'ElementsParams',
    'ElementsLiquidV1Params'
)
