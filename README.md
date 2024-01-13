Bitcoin Core 26.x Drivechain
============================

Bitcoin Core version 26 as a BIP 300 Drivechain with BIP 301 BMM

BIP 300: https://github.com/bitcoin/bips/blob/master/bip-0300.mediawiki

BIP 301: https://github.com/bitcoin/bips/blob/master/bip-0301.mediawiki

Learn more about Drivechain here: http://drivechain.info

<h4>The following BIPS are deployed for testing:</h4>

* BIP 118 Any Previous Output (https://github.com/bitcoin/bips/blob/master/bip-0118.mediawiki)
* BIP 119 Check Template Verify (https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki)
* BIP 345 Vaults (No BIP yet but will be 345 eventually?)

<h4>Configuration example (tests must be disabled for now):</h4>

`./configure --disable-tests --disable-bench --disable-fuzz-binary`
<h4>TODO & Known Issues:</h4>

So far things have only been tested in regtest mode, so starting with `--regtest` is recommended

* Drivechain tests
* BIP 118 tests
* BIP 119 tests
* BIP 345 tests
* Withdrawal Refunds disabled
* Chain param seeds empty
* HandleMainchainReorg functionality disabled
* Withdrawal object blind tx hash is a random uint256 instead of blinded tx hash - see https://github.com/LayerTwo-Labs/bitcoin/blob/6571f9c5e18dfc8987177cc2db452372225ef9aa/src/rpc/blockchain.cpp#L2793-L2796
* Peering hasn't been tested, and headers syncing is probably broken by BMM changes (TODO)
* No replay bytes / replay protection
* No DoS score code copied (where did that move?)

What is Bitcoin Core?
---------------------

https://bitcoincore.org

Bitcoin Core connects to the Bitcoin peer-to-peer network to download and fully
validate blocks and transactions. It also includes a wallet and graphical user
interface, which can be optionally built.

Further information about Bitcoin Core is available in the [doc folder](/doc).

License
-------

Bitcoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.
