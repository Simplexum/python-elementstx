This Python3 module implements support for Elements transactions.

It builds on top, and is intended to be used along with python-bitcointx library.

## Requirements

- [python-bitcointx](https://github.com/Simplexum/python-bitcointx) (version >= 1.0.0)
- [secp256k1-zkp](https://github.com/ElementsProject/secp256k1-zkp)

  Configure parameters for `secp256k1-zkp`:

```
    ./configure --enable-experimental \
                --enable-module-generator \
                --enable-module-rangeproof \
                --enable-module-surjectionproof \
                --enable-module-ecdh \
                --enable-module-recovery
```

## Usage:

With contextual switch to Elements parameters:

```python
import os
import elementstx
from bitcointx import ChainParams, get_current_chain_params
from bitcointx.wallet import CCoinKey, CCoinExtKey, CCoinAddress, P2PKHCoinAddress

with ChainParams('elements'):
    k = CCoinExtKey.from_seed(os.urandom(32))
    a = P2PKHCoinAddress.from_pubkey(k.derive_path("m/0'/0'/1").pub)
    print('example {} address: {}'.format(get_current_chain_params().name, a))
    assert CCoinAddress(str(a)) == a
```

With global switch to Elements parameters:

```python
from elementstx import ElementsParams
from bitcointx import select_chain_params

select_chain_params('elements')
# or, using the chain params class directly
select_chain_params(ElementsParams)

```

Without the switch of chain parameters:

```python
from elementstx.core import ElementsTransaction

transaction_data = read_tx_data()
tx = CElementsTransaction.deserialze(transaction_data)
print("Number of txout witnesses:", len(tx.wit.vtxoutwit))

```

# Example Code

See `examples/` directory.
