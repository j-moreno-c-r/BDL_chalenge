import json
from decimal import Decimal
import struct
from subprocess import run
from typing import Tuple, List, Dict
import hmac
import hashlib
from ecdsa import SigningKey, SECP256k1
from v1balance import base58_decode

# Constants for hardened and normal derivation
HARDENED_OFFSET = 0x80000000

def bcli(cmd: str):
    res = run(
            ["bitcoin-cli", "-signet"] + cmd.split(" "),
            capture_output=True,
            encoding="utf-8")
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        raise Exception(res.stderr.strip())


def get_p2wpkh_program(pubkey: bytes, version: int = 0) -> bytes:
    sha256_hash = hashlib.sha256(pubkey).digest()
    hash160_public_key = bytes([0x00,0x14])+hashlib.new('ripemd160', sha256_hash).digest()
    return hash160_public_key

def deserialize_key(b: bytes) -> Dict:
    # Parse version bytes
    version = b[:4]
    
    # Extract depth byte
    depth = b[4]

    # Read parent fingerprint
    parent_fingerprint = b[5:9]

    # Extract child number
    child_number = struct.unpack('>I', b[9:13])[0]

    # Get chain code
    chain_code = b[13:45]

    # Deserialize public key or private key data
    key_data = b[45:78]
    
    # Determine if it's a public or private key
    if key_data[0] == 0:
        # Private key (0x00 || ser256(k))
        private_key = key_data[1:33]
        is_private = True
    else:
        # Public key (serP(K))
        public_key = key_data[:]
        is_private = False

    return {
        "version": version.hex(),
        "depth": depth,
        "parent_fingerprint": parent_fingerprint.hex(),
        "child_number": child_number,
        "chaincode": chain_code.hex(),
        "is_private": is_private,
        "private_key" if is_private else "public_key": private_key.hex() if is_private else public_key.hex()
    }
#trocar no derive privchild
def bip32_derive_key(parent_key: bytes, parent_chaincode: bytes, index: int) -> Tuple[bytes, bytes]:
    """
    Derive a child private key and chain code using BIP32.
    """
    if index >= HARDENED_OFFSET:
        # Hardened derivation
        data = b'\x00' + parent_key + index.to_bytes(4, 'big')
    else:
        # Normal derivation
        parent_pubkey = derive_pubkey(parent_key)
        data = parent_pubkey + index.to_bytes(4, 'big')

    i = hmac.new(parent_chaincode, data, hashlib.sha512).digest()
    il, ir = i[:32], i[32:]
    child_key = (int.from_bytes(il, 'big') + int.from_bytes(parent_key, 'big')) % SECP256k1.order
    return child_key.to_bytes(32, 'big'), ir

#deixar como auxiliar
def parse_derivation_path(path: str) -> List[Tuple[int, bool]]:
    """
    Parse the derivation path (e.g., "m/84'/0'/0'/0/0") into a list of (index, hardened) tuples.
    """
    if not path.startswith("m/"):
        raise ValueError("Invalid derivation path")
    parts = path[2:].split("/")
    parsed_path = []
    for part in parts:
        if part.endswith("'"):
            parsed_path.append((int(part[:-1]), True))
        else:
            parsed_path.append((int(part), False))        

    return parsed_path

#adaptar para get pub from priv
def derive_pubkey(private_key: bytes) -> bytes:
    """
    Derive the compressed public key from a private key.
    """
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    vk = sk.verifying_key
    x, y = vk.pubkey.point.x(), vk.pubkey.point.y()
    compressed_pubkey = (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')
    return compressed_pubkey

#adptar para get_wallet_privs
def derive_privs_from_path(private_key: bytes, chaincode: bytes, path: str) -> bytes:
    """
    Derive the public key for a specific derivation path.
    """
    parsed_path = parse_derivation_path(path)
#    print(parsed_path)
    key, chain = private_key, chaincode
    for index, hardened in parsed_path:
        if hardened:
            index += HARDENED_OFFSET
        key, chain = bip32_derive_key(key, chain, index)
    return key,chain

def recover_wallet_state(tprv: str):
    all_bytes=base58_decode(tprv)
    main_desereliazed = deserialize_key(all_bytes)
    # Example private key and chain code (in bytes)
    private_key = bytes.fromhex(main_desereliazed["private_key"])
    chaincode = bytes.fromhex(main_desereliazed["chaincode"])
    # derivation_path = "m/84'/1'/0'/0/1"
    #84h/1h/0h/0/
    derivation_path = "m/84'/1'/0'/0"
    privatekey,chaincode= derive_privs_from_path(private_key, chaincode, derivation_path)
    publickey= derive_pubkey(privatekey)

    print(f"Derived Private Key: {privatekey.hex()}")
    print(f"Chaincode derived: {chaincode.hex()}")
    print(f"Derived Public Key: {publickey.hex()}")
    print(f"Address/Program from  pubkey: {get_p2wpkh_program(publickey).hex()}")


    #parte dos programas derivar as 2000 pubkeys e por fim endereços
    privs = []
    i = 0
    while len(privs) != 2000:
        privs.append(derive_privs_from_path(privatekey,chaincode,f"m/{i}"))
        i += 1 
    
    pubs = []
    for c in privs:
        pubs.append(derive_pubkey(c[0]))
    #print(pubs[0].hex())

    programs = []
    for d in pubs:
        programs.append(f"{get_p2wpkh_program(pubkey=d,version=0).hex()}")
    

    #print(programs[0])
    #print(programs)
    state = {
            "utxo": {},
            "balance": 0,
            "privs": privs,
            "pubs": pubs,
            "programs": programs,
        }
    print("state its finished📗")
    #print(pubs)
    
    """print(programs[0])
    return"""
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
                
                if pubkey in pubs:
                        # Remove this coin from our wallet state utxo pool
                        # so we don't double spend it later
                        scriptpkh = get_p2wpkh_program(pubkey).hex() 
                        if scriptpkh in state["utxo"]:
                            ammout = state["utxo"][scriptpkh]["amount"]
                            address = state["utxo"][scriptpkh]["address"]
                            print(f"🔴 spent this:{ammout} bitcoins, from that:{address} addres 💸")
                            del state["utxo"][scriptpkh]

            # Check every tx output for our own witness programs.
            # These are coins we have received.
            for out in tx["vout"]:
                scriptpkh = out["scriptPubKey"]["hex"]
                #print(programs[0])
                #print(scriptpkh)
                #return
                if scriptpkh in programs:
                    amount = Decimal(f"{out['value']:.8f}")
                    address = out["scriptPubKey"]["address"]
                    state["utxo"][scriptpkh] = {}
                    state["utxo"][scriptpkh]["txid"] = tx["txid"]
                    state["utxo"][scriptpkh]["amount"] = amount
                    state["utxo"][scriptpkh]["vout"] = out["n"] 
                    state["utxo"][scriptpkh]["address"] = address
                    state["utxo"][scriptpkh]["pubkeyhash"] = scriptpkh[4:]
                    print(f"🟢 Received {amount} Bitcoins in {address} 💰")
        print(h)
    
    for pkh, data in state["utxo"].items():
        data["amount"] = float(data["amount"])
        state["balance"] += float(data["amount"])
                    # Add to our total balance
                    # Keep track of this UTXO by its outpoint in case we spend it later
    return state


WALLET_NAME = "wallet_095"
EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9"
#✅
if __name__ == "__main__":
    print(f"{WALLET_NAME} {recover_wallet_state(EXTENDED_PRIVATE_KEY)['balance']}")