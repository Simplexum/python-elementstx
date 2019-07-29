# Elements examples

This directory contains four example programs that demonstrate usage of python-elementstx to work with Elements confidential transactions: building, serializing/deserializing, blinding and unblinding.

`unblind.py` takes hex-encoded transaction and blinding key, and successively tries to unblind the outputs of this transaction with the given blinding key.

`spend-to-confidential-address.py` takes hex-encoded transaction, spending key, unblinding key, and a destination address, and prints new hex-encoded transaction that spends the output of the input transaction that it can spend with the spending key. If this output is blinded, it then uses provided unblinding key to unblind the output. If the destination address provided is a confidential address, the code will blind the resulting transaction before signing it with spending key.

`asset-atomic-swap.py` works with two regtest Elements Core daemons, set up according to https://elementsproject.org/elements-code-tutorial/blockchain and uses their RPC API to issue assets and do other actions needed to demonstrate asset atomic swap. It features two participants: Alice and Bob, who issue new assets, and then atomically swap them by exchanging their swap offers, blinded (partial) transactions, and other data, building a final transaction out of the exchanged parts. The transaction is cooperatively signed by participants and then broadcasted within regtest network.

`confidential-cross-chain-atomic-swap.py` works with two Elements Core daemon, and regtest Bitcoin daemon, set up according to https://elementsproject.org/elements-code-tutorial/blockchain and uses their RPC API. It features two participants: Alice and Bob, who atomically swap regtest bitcoin to regtest elements-bitcoin by exchanging their pubkeys and shared blinding key, that allows Alice to construct a script in Elements regtest network such that for Bob to spend the transaction, it has to reveal the key that Alice can use to claim bitcoin from the address that Bob send his bitcoin for swap. If the protocol fails, participants try to reclaim their coins, because the scripts have timeout branch that allow the original owner to reclaim.

## Conventions

We assume you have python-elements sources unpacked in your home directory, under $HOME/python-elementstx.

`<cwd path>$` represends command prompt. Shell is assumed to be bash-compatible.

Make command is assumed to be GNU make.

Lines starting with `>` represent output from the commands.

# Setup

The command examples here assume the shell environment is set up as described in https://elementsproject.org/elements-code-tutorial/confidential-transactions and will use the shell aliases defined there.

Command examples also assume unix-like working environment.

To be able to work with confidential transaction beyond just serializing and deserializing them, the special experimental version of secp256k1 library, secp256k1-zkp is required. You can get it from https://github.com/ElementsProject/secp256k1-zkp. This experimental version of secp256k1 is currently not available as a ready-made package, so you will have to build the library yourself.

We assume you have secp256k1-zkp sources unpacked in your home directory, under $HOME/secp256k1-zkp path.

The examples will need to find python-elementstx installed in `PYTHONPATH`. Follow your preferred method for python module installation.

One of the possible methods to install the module for current user (not system-wide):

    ~/$ cd python-elementstx
    ~python-elementstx/$ pip3 install . --user

## Building secp256k1-zkp

Enter secp256k-zkp source directory

    ~/$ cd secp256k-zkp

Run configuration script for the library, specifying the experimental modules that we need to work with confidential transactions

    ~/secp256k1-zkp$ ./configure --enable-experimental \
                                 --enable-module-generator \
                                 --enable-module-rangeproof \
                                 --enable-module-surjectionproof \
                                 --enable-module-ecdh \
                                 --enable-module-recovery

Build the library

    ~/secp256k1-zkp$ make

Back to our home directory

    ~/secp256k1-zkp$ cd
    ~/$

The actual dynamic library file will be called `libsecp256k1.so`, and may conflict with system-installed secp256k1 library. To avoid this, we will not install the library into the system. To work with our examples, it is enough to set `LD_LIBRARY_PATH` to the path where the linker can find this version of the library. We can do so with the command:

    ~/$ export LD_LIBRARY_PATH=$HOME/secp256k1-zkp/.libs/ 

Now, the programs that are executed in the current shell session will use our newly built secp256k1-zkp library.

# Unblinding example

To run `unblind.py` example, we need to prepare the data that it will be unblinding.
Assuming the Elements tutorial environment for standalone blockchain are in place,
we will get an address from node2, along with its blinding key, send some funds from node1
to this address, and will run `unblind.py` to unblind the output destined to the node2 address.

Get new address from node2

    ~/$ e2-cli getnewaddress
    > Azpozaoz7Zsox4xh9AuSh6cLBQcP3RbJR6X3GT6Tkt5rf3NXDgEQfWL2qJnsnPhd5TeTfepBcTQKYFzs

Get the corresponding unconfidential address so we can check its presense in the output of getrawtransaction

    ~/$ e2-cli validateaddress Azpozaoz7Zsox4xh9AuSh6cLBQcP3RbJR6X3GT6Tkt5rf3NXDgEQfWL2qJnsnPhd5TeTfepBcTQKYFzs | jq '.unconfidential'
    > "XZsErNop3XtKxzPuLBrSD23r8YNcTmUSDL"

Dump blinding key for the address into `blkey` file

    ~/$ e2-cli dumpblindingkey Azpozaoz7Zsox4xh9AuSh6cLBQcP3RbJR6X3GT6Tkt5rf3NXDgEQfWL2qJnsnPhd5TeTfepBcTQKYFzs  > blkey

Send the sum of `1.2345` of the default asset from node1 to the address we got from node2 (notice that we are using `e1-cli` here

    ~/$ e1-cli sendtoaddress Azpozaoz7Zsox4xh9AuSh6cLBQcP3RbJR6X3GT6Tkt5rf3NXDgEQfWL2qJnsnPhd5TeTfepBcTQKYFzs 1.2345
    > 6cb06fdff623a40562dbd942b59c4c9b59bb0d7d918fa259980e76acb8bf4ea5

Check that the output to the address is blinded. The address `XZsErNop3XtKxzPuLBrSD23r8YNcTmUSDL` is in vout at index 1 (indexes start from 0)

    ~/$ e1-cli getrawtransaction 6cb06fdff623a40562dbd942b59c4c9b59bb0d7d918fa259980e76acb8bf4ea5 1| jq '.vout'

    > [
    >   {
    >     "value-minimum": 1e-08,
    >     "value-maximum": 687.19476736,
    >     "ct-exponent": 0,
    >     "ct-bits": 36,
    >     "valuecommitment": "09eaa110fc314fdb42f1e59570082b5339943f12be0397509ecc3e7c41de9540f0",
    >     "assetcommitment": "0be29d2b51f0de42b169fdc3f8cf13991612ee8ca21117684f79c24f19670dfb5a",
    >     "commitmentnonce": "037acb899113f1f21728d752b4455d038d66d9580d2f50cea20e61bb4ef5c0914b",
    >     "commitmentnonce_fully_valid": true,
    >     "n": 0,
    >     "scriptPubKey": {
    >       "asm": "OP_HASH160 d900857d3ae17c61669a22d56da7afb17506c738 OP_EQUAL",
    >       "hex": "a914d900857d3ae17c61669a22d56da7afb17506c73887",
    >       "reqSigs": 1,
    >       "type": "scripthash",
    >       "addresses": [
    >         "XX8e716gv993TwUdSmmfuB54u5r5D5QMdv"
    >       ]
    >     }
    >   },
    >   {
    >     "value-minimum": 1e-08,
    >     "value-maximum": 687.19476736,
    >     "ct-exponent": 0,
    >     "ct-bits": 36,
    >     "valuecommitment": "08557a3dedc60afeb2c41db7e4ab61342a9e28006427e48ff73624f40987cc05ec",
    >     "assetcommitment": "0a7e968bc217a78b2b1592fcc8984b5b002c253385024c4160db64afc6972de131",
    >     "commitmentnonce": "02251f2926992bb79e4e3c24b26e0d992f8408211fa8e87226a939784b621c2f09",
    >     "commitmentnonce_fully_valid": true,
    >     "n": 1,
    >     "scriptPubKey": {
    >       "asm": "OP_HASH160 f6ff3fdaf506e4ab3cb74ec33d1381b61a8fc558 OP_EQUAL",
    >       "hex": "a914f6ff3fdaf506e4ab3cb74ec33d1381b61a8fc55887",
    >       "reqSigs": 1,
    >       "type": "scripthash",
    >       "addresses": [
    >         "XZsErNop3XtKxzPuLBrSD23r8YNcTmUSDL"
    >       ]
    >     }
    >   },
    >   {
    >     "value": 0.0003966,
    >     "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
    >     "commitmentnonce": "",
    >     "commitmentnonce_fully_valid": false,
    >     "n": 2,
    >     "scriptPubKey": {
    >       "asm": "",
    >       "hex": "",
    >       "type": "fee"
    >     }
    >   }
    > ]

Get the hex dump of the transaction into `rawtx` file

    ~/$ e1-cli getrawtransaction 6cb06fdff623a40562dbd942b59c4c9b59bb0d7d918fa259980e76acb8bf4ea5 > rawtx

Run `unblind.py` example, specifying the wile with raw hex dump of the transaction, and file witb blinding key.
Notice that the code successfully unblinded vout at index 1, and shows us correct address and amount.

    ~/$ python-elementstx/examples/unblind.py rawtx blkey 

    > vout 0: cannot unblind: unable to rewind rangeproof
    >   destination address: XX8e716gv993TwUdSmmfuB54u5r5D5QMdv
    >   ct-exponent 0
    >   ct-bits 36
    >   value-minimum 1e-08
    >   value-maximum 687.19476736
    > 
    > vout 1: unblinded
    >   destination address:
    >      confidential:	 Azpozaoz7Zsox4xh9AuSh6cLBQcP3RbJR6X3GT6Tkt5rf3NXDgEQfWL2qJnsnPhd5TeTfepBcTQKYFzs
    >      unconfidential:	 XZsErNop3XtKxzPuLBrSD23r8YNcTmUSDL
    >   amount:		 1.2345
    >   blinding_factor:	 lx('ba9c5718b91265ac1e0846ad61e0bac8699c150b58e0cac48424e0586168321c')
    >   asset:		 CAsset('b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23')
    >   asset_blinding_factor: lx('dcf17dcee0c593471c340340c3d3416bccbde6ee2689ac20e0f508a2e57f5387')
    > 
    > vout 2: fee
    >   amount:		 0.0003966
    >   asset:		 CAsset('b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23')


# Spending to confidential address example

To run `spend-to-confidential-address.py` we will need the same environment as for the previous example, and we assume we have the same `rawtx` and `blkey` files that we generated in the previous example.

In addition to `rawtx` and `blkey` files we also need the key to spend the UTXO held at `XX8e716gv993TwUdSmmfuB54u5r5D5QMdv` address. We will dump it into `spendkey` file.

    ~/$ e2-cli dumpprivkey XZsErNop3XtKxzPuLBrSD23r8YNcTmUSDL > spendkey

We also need a destination address that our newly created transaction will send the funds to.

    ~/$ e1-cli getnewaddress
    > AzpnEJpGpUt9QM7UDkc51XtRZh9GeiQmG5nWJC2a7vzSJb8N47MGXj3VXCRQj5BNqYTmH771sMusrV7w

Run `spend-to-confidential-address.py`, specifying the raw hex dump of tx from previous example, a key to spend the UTXO, the blinding key to unblind the UTXO, and the destination address. Hexadecimal representation of a resulting transaction is placed into `blinded_tx` file. Note that the amount in satoshi matches the amount we sent to XX8e716gv993TwUdSmmfuB54u5r5D5QMdv earlier.

    ~/$ python-elementstx/examples/spend-to-confidential-address.py \
            rawtx spendkey blkey \
            AzpnEJpGpUt9QM7UDkc51XtRZh9GeiQmG5nWJC2a7vzSJb8N47MGXj3VXCRQj5BNqYTmH771sMusrV7w \
            > blinded_tx

    > Searching for ouptut with address XZsErNop3XtKxzPuLBrSD23r8YNcTmUSDL
    > Found at index 1
    >   amount: 123450000
    >   asset:  b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23
    > 
    > Successfully blinded 1 outputs
    > Successfully signed

Let's check the current balance at node2, before we send our newly build transaction. As expected, the balance for newasset is 1.2345, that we sent in prevoius example

    ~/$ e2-cli getbalance
    > {
    >     "newasset": 1.23450000,
    >     "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    > }

If getbalance does not show the expected balance, that might be because the second node do not yet accounted for incoming transaction we sent to it earlier. Do sync the balance, we can generate a block:

    ~/$ e1-cli generatetoaddress 1 AzpnEJpGpUt9QM7UDkc51XtRZh9GeiQmG5nWJC2a7vzSJb8N47MGXj3VXCRQj5BNqYTmH771sMusrV7w
    > [
    >   "943900fc6ce5351872020cc5d07d8563dc43f725f2d389a925501fbe76b2780c"
    > ]

Now let's send the transaction

    ~/$ e1-cli sendrawtransaction `cat blinded_tx`
    > 4a933d32238a2238f52fdfc6aad0fdc0be2cbaeb7bb48c482409c135d1ef8f81

And check that the balance has changed - we send the whole amount to the new address, which belongs to node1,
and now we do not see the 'newasset' balance - it was fully spent.

    ~/$ e2-cli getbalance
    > {
    >     "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    > }

The balance at node1 will be changed only after we generate a block. Let's see the current balance:

    ~/$ e1-cli getbalance
    > {
    >     "newasset": 999998.76510520,
    >     "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    > }

If we followed the instructions at https://elementsproject.org/elements-code-tutorial/blockchain, initial balance for newasset was 1000000. `1000000 - 999998.76510520 = 1.23489480`, a bit less than 1.2345, because the transaction fee was also paid from this sum.

Let's generate a new regtest block, so our new transaction will be confirmed

    ~/$ e1-cli generatetoaddress 1 AzpnEJpGpUt9QM7UDkc51XtRZh9GeiQmG5nWJC2a7vzSJb8N47MGXj3VXCRQj5BNqYTmH771sMusrV7w
    > [
    >   "6b58105845a8e9ebb45a164d771bf9263071fc155e656974053c5dcfda4f58d3"
    > ]

And then check the balance at node1

    ~/$ e1-cli getbalance
    > {
    >     "newasset": 999999.99921040,
    >     "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    > }

We can see that the balance is increased by `999999.99921040 - 999998.76510520 = 1.23410520`, this is less than 1.2345, because `spend-to-confidential-address.py` uses the same amount for fee that was used in source transaction. As we can see from the output of getrawtransaction above, the fee was 0.00039480, and  1.23410520 plus 0.00039480 is 1.2345.
    
# Asset atomic swap example

In contrast to usual cross-chain atomic swap which is performed by using [hash time locked contracts](https://en.bitcoin.it/wiki/Hash_Time_Locked_Contracts), the support for assets in Elements allows to perform atomic swaps just by cooperatively signing a transaction that have UTXOs holding different assets from different participants as inputs, and have an ouptuts that distribute the assets to participants according to their agreement. Because participants sign their inputs using `SIGHASH_ALL` type of transaction signature hash, for which all inputs and outputs of the transaction are commited to the signature hash, no participant can alter the transaction without invalidating signatures of the other participants as a result. The atomicity of the swap is in the fact that the assets will be transferred if and only if only when the cooperatively prepared and signed transaction is confirmed.

In the `asset-atomic-swap.py` example, two participants of an asset atomic swap are represented by two processes that communicate via `mulitprocessing.Pipe` mechanism provided by standard `multiprocessing` python module. Participant processes connect to Elements RPC API of Elements daemons that are started according to the procedure described at https://elementsproject.org/elements-code-tutorial/blockchain.

The environment is assumed to be the same as with the previous examples.

The example will need to know the asset that is used to pay the fee in our regtest network. If we look at getrawtransaction output in `unblind.py` example, we will see that the asset for fee is `b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23`.

To run an example, we will specify two directories of Elements daemons, that reside in our home directory, and the asset for fee. The output of the example will be descriptive enough to have an idea of what is happening.

    ~/$ python-elementstx/examples/asset-atomic-swap.py \
            ~/elementsdir1 ~/elementsdir2/ \
            b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23

    > Alice: Connecting to Elements daemon RPC interface, using config in ~/elementsdir1/elements.conf
    > Alice: Issuing my own new asset, amount: 1.0
    > Bob: Connecting to Elements daemon RPC interface, using config in ~/elementsdir2/elements.conf
    > Bob: Issuing my own new asset, amount: 1.0
    > Alice: The asset is 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49
    > Alice: Getting unspent utxo for asset 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49
    > Alice: Unspent utxo for asset 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49 is d7c5334349c27df5a3afee3cabd20ff52f41ce86da0fe0a0f9fc2ddda6d124aa:0
    > Alice: Retrieving private key to spend UTXO (source address 2drAQaAFZyf7qduXECgk79JsKs97G8zTypT)
    > Alice: Issuing my own new asset, amount: 1.0
    > Bob: The asset is 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62
    > Bob: Getting unspent utxo for asset 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62
    > Bob: Unspent utxo for asset 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62 is 84aa5da8c58b390836d776e8de5471c03bcdd64686a020feebf6f235841221da:1
    > Bob: Retrieving private key to spend UTXO (source address 2dm7PC3tWtDJ17GYi3dvSJWMnnYj58Yrqz4)
    > Bob: Setting up communication with Alice
    > Alice: The asset is f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55
    > Alice: Getting unspent utxo for asset f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55
    > Alice: Unspent utxo for asset f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55 is 3608a9d88f9638c594ce954df2310be1635aa026f99d35efcb40a5d1a2be5111:0
    > Alice: Retrieving private key to spend UTXO (source address 2dfdS4BBCvP62VKJ8N7Pbwt2JqHvZ6bYXxe)
    > Alice: Searching for utxo for fee asset
    > Alice: Getting change address for fee asset
    > Alice: Generating new address and retrieving blinding key for it
    > Alice: Will use utxo 8ccae4da74e3f571ae0c8125befff419bd29a624bd1958547e0e98250a6258b8:3 (amount: 0.00091280) for fee, change will go to CTEuajcMJYaYSmtsfpgp75p7K4EvajJKHtSnMXgcMTmkTvoXJtpsAS6SMWuJH5EExo4AQEmxMwYRz1Gy
    > Alice: Setting up communication with Bob
    > Bob: Waiting for Alice to send us an offer array
    > Alice: Waiting for txid d7c5334349c27df5a3afee3cabd20ff52f41ce86da0fe0a0f9fc2ddda6d124aa to confim
    > Alice: Waiting for txid 3608a9d88f9638c594ce954df2310be1635aa026f99d35efcb40a5d1a2be5111 to confim
    > Alice: Waiting for txid 84aa5da8c58b390836d776e8de5471c03bcdd64686a020feebf6f235841221da to confim
    > Alice: Sending offer to Bob
    > Bob: Alice's offers are [AtomicSwapOffer(asset='466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49', amount=100000000), AtomicSwapOffer(asset='f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55', amount=100000000)], sending my offer
    > Bob: Waiting for Alice's address and assetcommitments
    > Alice: Current asset balance:
    > Alice: 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49: 1.00000000
    > Alice: f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55: 1.00000000
    > Alice: 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62: 0E-8
    > Alice: Bob responded with his offer: AtomicSwapOffer(asset='4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62', amount=100000000)
    > Alice: Generating new address and retrieving blinding key for it
    > Alice: Sending my address and assetcommitments for my UTXOs to Bob
    > Bob: Current asset balance:
    > Bob: 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49: 0E-8
    > Bob: f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55: 0E-8
    > Bob: 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62: 1.00000000
    > Bob: Alice's address: CTEsSBZrt7NGu9goHtNxSH4vtQ1MnmkHcEtnBCeLLDsmmP53NT7Yg77SvYmjYnadcpJAAvYC8Ph1ukJd
    > Bob: Alice's assetcommitments: ['0bc6bceb4e1a35e0625a750b7ad1c44d3e19f0d2fae9017992dc8935ea39a24403', '0ae23d6b747636f029cb2dcd185d7fca1e6de1b98bb19084de3e7c87d3d909d9b6', '0b3c9380a617bbc2e8e0544417077f88ee2690b6a4e37cf904adb647dbad35de78']
    > Bob: Successfully blinded partial transaction, sending it to Alice
    > Bob: Generating addresses to receive Alice's assets
    > Bob: Generating new address and retrieving blinding key for it
    > Alice: Got partial blinded tx of size 2888 bytes from Bob
    > Bob: Generating new address and retrieving blinding key for it
    > Bob: Sending my addresses and assetcommitment to Alice
    > Alice: Asset and amount in partial transaction matches Bob's offer
    > Alice: Bob's addresses to receive my assets: ['CTEn4RBnfhCqCXo1mNJ3Kcbtq3oLRq2pkpwE5ap5Jz8uEbrcRGFm2Krsx34fZaaFncDLnCUu94JovY66', 'CTEmde7LxpFJwEw1815pxkho2YpMRT2DidRDuPnE92Huz6MCJLQMZNEZhA9CGWUu93dfCviSqaYBndXj']
    > Alice: Successfully blinded the combined transaction, will now sign
    > Alice: Signed my inputs, sending partially-signed transaction to Bob
    > Bob: Got partially signed tx of size 11885 bytes from Alice
    > Bob: Assets and amounts in partially signed transaction match Alice's offer
    > Bob: Signed the transaction from my side, sending
    > Bob: Sent with txid 2dec73424522e82e4e8200129821e523c35ceb20f84726574ce4103ba9a2e758
    > Alice: Waiting for txid 2dec73424522e82e4e8200129821e523c35ceb20f84726574ce4103ba9a2e758 to confim
    > Alice: Current asset balance:
    > Alice: 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49: 0E-8
    > Alice: f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55: 0E-8
    > Alice: 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62: 1.00000000
    > Alice: Asset atomic swap completed successfully
    > Bob: Current asset balance:
    > Bob: 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49: 1.00000000
    > Bob: f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55: 1.00000000
    > Bob: 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62: 0E-8
    > Bob: Asset atomic swap completed successfully

# Confidential cross-chain atomic swap example

In contrast to usual cross-chain atomic swap which is performed by using [hash time locked contracts](https://en.bitcoin.it/wiki/Hash_Time_Locked_Contracts), the support for more script operations in Elements allows to perform atomic swaps that are done not by revealing a hash, but by revealing the private key. The contract script is written in such a way that to spend the Elements UTXO via the swap branch, the participant discloses the private key that is needed to spend the Bitcoin UTXO. This private key is additionally blinded by another key, that the swap participants share before the swap. This way, outside observers cannot directly link the transactions of this swap by checking for the hash value, as it is possible with HTLC. Correlation via timing and via special script used are still possible, but note that values in Elemens transactin are blinded. There is even better way to get the same 'confidential swap' mechanism using adaptor signatures, that is possible with Shnorr signature algorithm, but for the purpose of the example of the functionality of the library it does not matter that much.

The environment is assumed to be the same as with the previous examples.

The example will need to know the asset that is used to pay the fee in our regtest network. If we look at getrawtransaction output in `unblind.py` example, we will see that the asset for fee is `b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23`.

To run an example, we will specify a directory of Bitcoin daemon, and of Elements daemon, that reside in our home directory, and the asset for fee. The output of the example will be descriptive enough to have an idea of what is happening.

    ~/$ python-elementstx/examples/confidential-cross-chain-atomic-swap.py \
            ~/bitcoindir/ ~/elementsdir2/ b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23

    > Alice: Connecting to Elements daemon RPC interface, using config in ~/bitcoindir/bitcoin.conf
    > Alice: Connecting to Elements daemon RPC interface, using config in ~/elementsdir2/elements.conf
    >   Bob: Connecting to Elements daemon RPC interface, using config in ~/bitcoindir/bitcoin.conf
    > Miner: Connecting to Elements daemon RPC interface, using config in ~/bitcoindir/bitcoin.conf
    >   Bob: Connecting to Elements daemon RPC interface, using config in ~/elementsdir2/elements.conf
    > Alice: Sending pubkeys to Bob
    >   Bob: Waiting for blinding key from Alice
    > Alice: Sending the blinding key to Bob
    > Miner: Connecting to Elements daemon RPC interface, using config in ~/elementsdir2/elements.conf
    >   Bob: Pubkey for blinding key: 024bb33b1cc7a96de3a26a11e884c8c02a28da4b3bc3a64b4e636f99c10761a657
    >   Bob: The pubkey of the combined key to be revealed: 03b4f2b22918dcfc6b51f4d22ef4113131ba184a5d72706455ac27e4bb918da3ea
    >   Bob: Sending my pubkeys to Alice
    >   Bob: combined_btc_spend_pubkey: 03d176450a3fe8d054599259c0bfe6d34db3d374837b34ee3c9a1e271e6754b358
    > Alice: Pubkey of the key to be revealed: 02dfe345ec991a8038dadd3868d01bb90291b1396c19ea80a047be9e2213aaf061
    > Alice: Bob's Elements-side pubkey: 033292c6c6941d8babeb2c4179a67ed4666243b7c4a49764e622ff998912308968
    >   Bob: Created Bitcoin-side swap contract, size: 75
    >   Bob: Contract address: bcrt1qffnh503g9jrjvn0a0ul8yjwexjz3hcknkuhzhjr8q7vdqm46js4qln859u
    >   Bob: Sending 1.01 to bcrt1qffnh503g9jrjvn0a0ul8yjwexjz3hcknkuhzhjr8q7vdqm46js4qln859u
    > Alice: Created Elemets-side swap contract, size: 136
    > Alice: Contract address:
    > 	confidential: Azpm29uXyKtMA3osswx8PfEfup4mMu66ACVGMtjzPofmuKK6hWhggiN4x4QyLz77w7nk8uYsmCke5ngk
    > 	unconfidential: XSpxjuyi5isURzbjFuquncDiTQWAUsW9Z5
    >   Bob: Waiting for Bitcoin txid aa2eeb7591fcc24e19428609d84cbc19f2c709c5c755096ee057fca6a62fca38 to confim
    > Alice: Looking for this address in transaction aa2eeb7591fcc24e19428609d84cbc19f2c709c5c755096ee057fca6a62fca38 in Bitcoin
    > Alice: Found the address at output 0
    > Alice: Bitcoin amount match expected values
    > Alice: Sending 1.01 to Azpm29uXyKtMA3osswx8PfEfup4mMu66ACVGMtjzPofmuKK6hWhggiN4x4QyLz77w7nk8uYsmCke5ngk
    > Alice: Waiting for Elements txid a391c7c5fed5cc21328a1c06c2615b83d6814166e21e13770cb699c524c046b3 to confim
    >   Bob: Got Elements contract address from Alice: XSpxjuyi5isURzbjFuquncDiTQWAUsW9Z5
    >   Bob: Looking for this address in transaction a391c7c5fed5cc21328a1c06c2615b83d6814166e21e13770cb699c524c046b3 in Elements
    >   Bob: Found the address at output 1
    >   Bob: The asset and amount match expected values. lets spend it.
    >   Bob: I will claim my Elements-BTC to AzpqkXa2nZXE6fTrXRu3ML5pdhHpxEvTy4x5rSbexV1Apwz2mVrzQwnRWStCs7oubuxUQ4opuuYhQ7wp
    >   Bob: Sending my spend-reveal transaction
    >   Bob: Waiting for Elements txid 00bb151dc85a29622c208cc05b5fb97f473660ff9f7359157f807ab14e3fa4f7 to confim
    > Alice: Got txid for spend-reveal transaction from Bob (00bb151dc85a29622c208cc05b5fb97f473660ff9f7359157f807ab14e3fa4f7)
    > Alice: Waiting for Elements txid 00bb151dc85a29622c208cc05b5fb97f473660ff9f7359157f807ab14e3fa4f7 to confim
    > Alice: Transaction input 0 seems to contain a script we can recover the key from
    > Alice: recovered key pubkey: 03b4f2b22918dcfc6b51f4d22ef4113131ba184a5d72706455ac27e4bb918da3ea
    > Alice: recovered unblined key pubkey: 02dfe345ec991a8038dadd3868d01bb90291b1396c19ea80a047be9e2213aaf061
    > Alice: Successfully recovered the key. Can now spend Bitcoin from bcrt1qffnh503g9jrjvn0a0ul8yjwexjz3hcknkuhzhjr8q7vdqm46js4qln859u
    >   Bob: Got my Elements-BTC. Swap successful (at least for me :-)
    > Alice: Sending my Bitcoin-claim transaction
    > Alice: Waiting for Bitcoin txid da5c7d41a9b5e87f533026b102dd84f6f1f85995461011c360b606b204db41af to confim
    > Alice: Got my Bitcoin. Swap successful!
    > Terminating the miner process

That's all.

Please study the source of the examples and explore the state of the regtest network after they have ran.
