from typing import List, Tuple
import hmac
import hashlib

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

# Example usage (assuming you have the root key and chaincode):
# root_key = b'your_root_private_key_here'
# root_chaincode = b'your_root_chaincode_here'
# path = [(0x80000000 + 44, True), (0x80000000 + 0, True), (0x80000000 + 0, True)]
# child_keys = get_wallet_privs(root_key, root_chaincode, path)
