# Connect to the network

The goal of this project is to connect to a real Bitcoin node and retrieve the header of the mythic block 170 and the data from the first Bitcoin transaction ever from Satoshi to Hal Finney.

No RPC this time! Your program should retrieve data in the p2p network. Network messages are documented in the [Bitcoin Wiki](https://en.bitcoin.it/wiki/Protocol_documentation#getblocks) and important parameters are documented in the [bitcoin.org website](https://developer.bitcoin.org/reference/p2p_networking.html).

**Full node IP: `84.247.182.145:8333`**.

Tip: During development, spawn a `bitcoind` node in `regtest` mode and validate your messages before going to the real network. 

## Network handshake

Suppose you are node A and wnats to connect to node B. Open a TCP socket, connect it to the IP and port of peer B and exchange `version` and `verack` messages:

1. A opens a TCP socket to B and send a `version` message.
2. B responds with a `verack` message.
3. B sends a `version` message.
4. A sends a `verack` message.

Note that there's no authentication, and it's up to the nodes to verify the data they receive. If you send bad data, expect to get banned or disconnected.

## Network messages

You probably need to implement serialization and deserialization of the following messages:

- `getheaders` (serialize) which is answered by `headers` (deserialize);
- `getdata` (serialize) which is answered by `tx` (deserialize) or `block` (deserialize) messages.

# Submission

Your program must produce two files (see examples below):
- `solution/header.txt` with exactly one line containing the hex serialization of the block header;
- `solution/transaction.txt` with exactly one line containing the hex serialization of the transaction.

You are allowed to write your wallet code in any of the following programming languages:

Python
C
C++
C#
Rust
Go

The reviewer will run the bash script `solution/run_network.sh` which MAY BE EDITED BY STUDENTS if you need to install additional dependencies.

## Example output

``` shell
$ cat solution/header.txt
0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e70

$ cat solution/transaction.hex
0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000
```




