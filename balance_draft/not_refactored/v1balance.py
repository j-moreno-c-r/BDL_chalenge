from decimal import Decimal
from typing import List, Tuple
import hashlib
import ecdsa
import hmac
import json

# Provided by administrator
WALLET_NAME = "wallet_095"
EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9"
#wpkh(tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9/84h/1h/0h/0/*)#uadxj6umj
#wallet_095 97.92966532 need to be this balance
#wallet_095 97.92966532000003

# Decode a base58 string into an array of bytes✅
def base58_decode(base58_string: str) -> bytes:
    # Convert Base58 string to a big integer
    # Convert the integer to bytes
    # Chop off the 32 checksum bits and return
    # BONUS POINTS: Verify the checksum!
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    
    for c in base58_string:
        num *= 58
        num += base58_alphabet.index(c)

    pad = len(base58_string) - len(base58_string.lstrip('1'))
    result_bytes = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    return b'\x00' * pad + result_bytes

# Deserialize the extended key bytes and return a JSON object
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)✅
def deserialize_key(b: bytes) -> object:
    version = b[0:4]
    depth = b[4:5]
    fingerprint = b[5:9]
    child_number = b[9:13]
    chain_code = b[13:45]
    key_data = b[45:78]
    checksum = b[78:82]
    
    private_key_hex = b.hex()
    version_hex = version.hex()
    depth_hex = depth.hex()
    fingerprint_hex = fingerprint.hex()
    child_number_hex = child_number.hex()
    chain_code_hex = chain_code.hex()
    key_data_hex = key_data.hex()
    checksum_hex = checksum.hex()

    json_object = {
        "version": version_hex,
        "depth": depth_hex,
        "fingerprint": fingerprint_hex,
        "child_number": child_number_hex,
        "chaincode": chain_code_hex,
        "key_data": key_data_hex,
        "checksum": checksum_hex, 
        "private_key": private_key_hex, 
    }

    final_json = json.dumps(json_object, indent=4)
    return final_json

# Derive the secp256k1 compressed public key from a given private key
# BONUS POINTS: Implement ECDSA yourself and multiply you key by the generator point!✅
def get_pub_from_priv(priv: bytes) -> bytes:
     # Ensure the byte array is 32 bytes long (256 bits)
    if len(priv) != 32:
        raise ValueError("Private key must be 32 bytes long")
    
    # Create a private key object using the secp256k1 curve
    sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    
    # Get the corresponding public key
    vk = sk.get_verifying_key()
    
    # Get the compressed public key
    compressed_public_key = vk.to_string(encoding='compressed')
    
    return compressed_public_key


# Perform a BIP32 parent private key -> child private key operation
# Return a JSON object with "key" and "chaincode" properties as bytes
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key ✅
def derive_priv_child(key: bytes, chaincode: bytes, index: int, hardened: bool) -> dict:
    # Constants for secp256k1 curve
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    # If the child is a hardened derivation, we use the parent key in its extended form (with leading 0x00)
    if hardened:
        i = (index + 0x80000000).to_bytes(4, byteorder="big")
        data = b'\x00' + key + i
    else:
        # For non-hardened derivation, we use the public key of the parent
        priv_key = ecdsa.SigningKey.from_string(key, curve=ecdsa.SECP256k1)
        pub_key = priv_key.get_verifying_key().to_string(encoding='compressed')
        data = pub_key + index.to_bytes(4, 'big')

    # Perform HMAC-SHA512 to derive the child key and chain code
    I = hmac.new(chaincode, data,  digestmod=hashlib.sha512).digest()
    
    # The first 32 bytes are the IL (child key)
    IL = I[:32]
    # The last 32 bytes are the IR (new chain code)
    IR = I[32:]

    # Calculate the child key
    child_key = (int.from_bytes(IL, 'big') + int.from_bytes(key, 'big')) % N
    
    if child_key == 0:
        raise ValueError("Invalid private key derived. Try again with a different index.")

    return {
        "key": child_key.to_bytes(32, 'big'),
        "chaincode": IR
    }


# Given an extended private key and a BIP32 derivation path,
# compute the first 2000 child private keys.
# Return an array of keys encoded as bytes.
# The derivation path is formatted as an array of (index: int, hardened: bool) tuples,,
# Constants for BIP32✅

def get_wallet_privs(key: bytes, chaincode: bytes, path: List[Tuple[int, bool]]) -> List[bytes]:
    keys= []
    for index, hardened in path:
        base = derive_priv_child(key=key,chaincode=chaincode,index=index,hardened=hardened)
        keys.append(base["key"]) 
    return keys       

# Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed public key.
# Return a bytes array to be compared with the JSON output of Bitcoin Core RPC getblock
# so we can find our received transactions in blocks.
# These are segwit version 0 pay-to-public-key-hash witness programs.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-P2WPKH ✅


# Assuming Bitcoin Core is running and connected to signet using default datadir,
# execute an RPC and return its value or error message.
# https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path
# Examples: bcli("getblockcount")
#           bcli("getblockhash 100")✅


# Recover the wallet state from the blockchain:
# - Parse tprv and path from descriptor and derive 2000 key pairs and witness programs
# - Request blocks 0-310 from Bitcoin Core via RPC and scan all transactions
# - Return a state object with all the derived keys and total wallet balance✅
def recover_wallet_state(tprv: str):
    # Generate all the keypairs and witness programs to search for
    all_bytes=base58_decode(tprv)
    json_desereliazed = deserialize_key(all_bytes)
    main_dict = json.loads(json_desereliazed)
    #/84h/1h/0h/0/

    #84h
    priv_child1:dict = derive_priv_child(
                                    bytes.fromhex(main_dict["key_data"]),
                                    bytes.fromhex(main_dict["chain_code"]),
                                    index=84,
                                    hardened=True
                                    )
    #1h
    priv_child2 = derive_priv_child(
                                    priv_child1["key"],
                                    priv_child1["chaincode"],
                                    index=1,
                                    hardened=True
                                    )

    #0h
    priv_child3 = derive_priv_child(
                                    priv_child2["key"],
                                    priv_child2["chaincode"],
                                    index=0,
                                    hardened=True
                                    )

    #0
    priv_child4 = derive_priv_child(
                                    priv_child3["key"],
                                    priv_child3["chaincode"],
                                    index=0,
                                    hardened=False
                                    )
    

    derivation_path = [(index, False) for index in range(2000)]
    
    privs = get_wallet_privs(key=priv_child4["key"],chaincode=priv_child4["chaincode"],path=derivation_path)

    pubs = []
    for c in privs:
        pubs.append(get_pub_from_priv(c))

    #programs are in asm in my implementation
    programs = []
    for d in pubs:
        programs.append(f"0 {get_p2wpkh_program(pubkey=d,version=0).hex()}")

    # Prepare a wallet state data structure
    state = {
        "utxo": {},
        "balance": 0,
        "privs": privs,
        "pubs": pubs,
        "programs": programs
    }
    """print(programs)
    return"""
    #print(state["pubs"][0])
    # Scan blocks 0-310
    #bitcoin-cli -signet deriveaddresses
    height = 310
    for h in range(height + 1):
        if h == 0:
            continue
        blockhash = bcli(cmd=f"getblockhash {h}")
        block = bcli(cmd=f"getblock {blockhash}")
        txs = json.loads(block)["tx"]
                 # Scan every tx in every block
        for tx in txs:
            rawtxdecoded = bcli(cmd=f"getrawtransaction {tx} true")
            tx = json.loads(rawtxdecoded)

            # Check every tx input (witness) for our own compressed public keys.
            # These are coins we have spent.
            for inp in tx["vin"]:
                if "txinwitness" not in inp:
                    continue

                txinwit = inp["txinwitness"]

                if len(txinwit) != 2:
                    continue

                pubkey = bytes.fromhex(txinwit[1])
                #print(pubkey)

                if pubkey in pubs:
                    # Remove this coin from our wallet state utxo pool
                    # so we don't double spend it later
                    scripvin = get_p2wpkh_program(bytes.fromhex(pubkey)).hex() 
                    if scripvin in state["utxo"]:
                        ammout = state["utxo"][scripvin]["ammount"]
                        address = state["utxo"][scripvin]["address"]
                        print(f"🔴 spent this:{ammout} bitcoins, from that:{address} addres 💸")
                        del state["utxo"][scripvin]

            # Check every tx output for our own witness programs.
            # These are coins we have received.
            for out in tx["vout"]:
                scrptvout = out["scriptPubKey"]["asm"]
                #print(programs[0])
                #print(scrptvout)
                #return
                if scrptvout in programs:
                    ammout = Decimal(f"{out['value']:.8f}")
                    address = out["scriptPubKey"]["address"]
                    state["utxo"][scrptvout] = {}
                    state["utxo"][scrptvout]["txid"] = tx["txid"]
                    state["utxo"][scrptvout]["ammount"] = ammout
                    state["utxo"][scrptvout]["vout"] = out["n"] 
                    state["utxo"][scrptvout]["address"] = address
                    state["utxo"][scrptvout]["pubkeyhash"] = scrptvout[4:]
                    print(f"🟢 Received {ammout} Bitcoins in {address} 💰")
        print(h)
    
    for data in state["utxo"].items():
        data["ammount"] = float(data["ammount"])
        state["balance"] = float(data["ammount"])
                    # Add to our total balance
                    # Keep track of this UTXO by its outpoint in case we spend it later
    return state

#✅
if __name__ == "__main__":
    print(f"{WALLET_NAME} {recover_wallet_state(EXTENDED_PRIVATE_KEY)['balance']}")
