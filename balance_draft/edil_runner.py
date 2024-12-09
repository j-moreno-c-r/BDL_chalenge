from decimal import Decimal
from subprocess import run
from typing import List, Tuple
import hashlib
import ecdsa
import hmac
import json
import jq

# Provided by administrator
WALLET_NAME = "wallet_095"
EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9"
#wpkh(tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9/84h/1h/0h/0/*)#uadxj6umj
#wallet_095 97.92966532 need to be this balance


# Decode a base58 string into an array of bytes
def base58_decode(base58_string: str) -> bytes:
    # Convert Base58 string to a big integer
    # Convert the integer to bytes
    # Chop off the 32 checksum bits and return
    # BONUS POINTS: Verify the checksum!
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    
    for c in base58_string:
        num *= 58
        num += base58_alphabet.find(c)

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
# 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
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
        "chain_code": chain_code_hex,
        "key_data": key_data_hex,
        "checksum": checksum_hex, 
        "private_key": private_key_hex, 
    }

    final_json = json.dumps(json_object, indent=4)
    return final_json

# Derive the secp256k1 compressed public key from a given private key
# BONUS POINTS: Implement ECDSA yourself and multiply you key by the generator point!
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
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key
def derive_priv_child(key: bytes, chaincode: bytes, index: int, hardened: bool) -> dict:
    # Constants for secp256k1 curve
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    # If the child is a hardened derivation, we use the parent key in its extended form (with leading 0x00)
    if hardened:
        data = b'\x00' + key + index.to_bytes(4, 'big')
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
# The derivation path is formatted as an array of (index: int, hardened: bool) tuples.

# Constants for BIP32
BIP32_HARDENED = 0x80000000
SECP256K1_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)
SECP256K1_G = int('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16)

def get_wallet_privs(key: bytes, chaincode: bytes, path: List[Tuple[int, bool]]) -> List[bytes]:
    # Derive the root key first
    for index, hardened in path:
        if hardened:
            data = b'\x00' + key + index.to_bytes(4, 'big')
        else:
            raise ValueError("Non-hardened derivation is not supported from the root. Please provide a full derivation path starting with hardened indices.")
        
        I = hmac.new(chaincode, data, hashlib.sha512).digest()
        IL = I[:32]
        IR = I[32:]
        
        # Compute child key
        if int.from_bytes(IL, 'big') >= SECP256K1_ORDER:
            raise ValueError("Invalid private key derived")
        
        ki = (int.from_bytes(key, 'big') + int.from_bytes(IL, 'big')) % SECP256K1_ORDER
        if ki == 0:
            raise ValueError("Private Key is zero: collission, rederive with different index/path.")
        
        key = ki.to_bytes(32, 'big')
        chaincode = IR
    
    # Now derive the first 2000 child keys from the derived parent key
    child_keys = []
    for i in range(2000):
        data = b'\x00' + key + i.to_bytes(4, 'big')
        
        I = hmac.new(chaincode, data, hashlib.sha512).digest()
        IL = I[:32]
        IR = I[32:]
        
        # Compute child key
        if int.from_bytes(IL, 'big') >= SECP256K1_ORDER:
            raise ValueError("Invalid private key derived")
        
        ki = (int.from_bytes(key, 'big') + int.from_bytes(IL, 'big')) % SECP256K1_ORDER
        if ki == 0:
            raise ValueError("Private Key is zero: collission, rederive with different index/path.")
        
        child_key = ki.to_bytes(32, 'big')
        child_keys.append(child_key)
    
    return child_keys

# Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed public key.
# Return a bytes array to be compared with the JSON output of Bitcoin Core RPC getblock
# so we can find our received transactions in blocks.
# These are segwit version 0 pay-to-public-key-hash witness programs.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-P2WPKH
def get_p2wpkh_program(pubkey: bytes, version: int = 0) -> bytes:
    # Step 1: Hash the compressed public key with SHA-256
    sha256_pubkey = hashlib.sha256(pubkey).digest()
    
    # Step 2: Hash the result with RIPEMD-160 to get the pubkeyhash
    ripemd160_pubkeyhash = hashlib.new('ripemd160', sha256_pubkey).digest()
    
    # Step 3: Construct the witness program
    # For p2wpkh, version 0 is represented as 0x00 followed by the length of the hash (0x14 for 20 bytes)
    witness_program = b'\x00\x14' + ripemd160_pubkeyhash
    
    return witness_program

# Assuming Bitcoin Core is running and connected to signet using default datadir,
# execute an RPC and return its value or error message.
# https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path
# Examples: bcli("getblockcount")
#           bcli("getblockhash 100")
def bcli(cmd: str):
    res = run(
            ["bitcoin-cli", "-signet"] + cmd.split(" "),
            capture_output=True,
            encoding="utf-8")
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        raise Exception(res.stderr.strip())


# Recover the wallet state from the blockchain:
# - Parse tprv and path from descriptor and derive 2000 key pairs and witness programs
# - Request blocks 0-310 from Bitcoin Core via RPC and scan all transactions
# - Return a state object with all the derived keys and total wallet balance
def recover_wallet_state(tprv: str):
    # Generate all the keypairs and witness programs to search for
    all_bytes=base58_decode("tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9")
    json_desereliazed = deserialize_key(all_bytes)
    main_dict = json.loads(json_desereliazed)
    parent_private_key = bytes.fromhex(main_dict["key_data"]) 
    parent_chain_code = bytes.fromhex(main_dict["chain_code"])
    derivation_path = [
        (84 | BIP32_HARDENED, True),
        (0 | BIP32_HARDENED, True),
        (0 | BIP32_HARDENED, True)
    ]

    privs = get_wallet_privs(parent_private_key,parent_chain_code,derivation_path)
    pubs = []
    for c in privs:
        pubs+=get_pub_from_priv(c) 
        
    programs = []
    for d in pubs:
        programs+=get_p2wpkh_program(d)

    # Prepare a wallet state data structure
    state = {
        "utxo": {},
        "balance": 0,
        "privs": privs,
        "pubs": pubs,
        "programs": programs
    }

    # Scan blocks 0-310
    height = 310
    for h in range(height + 1):
        block_information = bcli(f"getblock{bcli(f"getblockhash{h}")}")
        location_tx_jq = '.tx[].txid'
        txs = jq.one(location_tx_jq, block_information)
        # Scan every tx in every block
        for tx in txs:
            transaction_information = bcli(f"decoderawtransaction{bcli(f"getrawtransaction{tx}")}")
            # Check every tx input (witness) for our own compressed public keys.
            # These are coins we have spent.
            for inp in tx["vin"]:
                  
                    # Remove this coin from our wallet state utxo pool
                    # so we don't double spend it later

            # Check every tx output for our own witness programs.
            # These are coins we have received.
            for out in tx["vout"]:
                    # Add to our total balance

                    # Keep track of this UTXO by its outpoint in case we spend it later

    return state


if __name__ == "__main__":
    print(f"{WALLET_NAME} {recover_wallet_state(EXTENDED_PRIVATE_KEY)['balance']}")
