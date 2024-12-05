import hashlib
from ecdsa import SECP256k1, VerifyingKey, SigningKey

def derive_priv_child(key: bytes, chaincode: bytes, index: int, hardened: bool) -> dict:
    # Constants for secp256k1 curve
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    # If the child is a hardened derivation, we use the parent key in its extended form (with leading 0x00)
    if hardened:
        data = b'\x00' + key + index.to_bytes(4, 'big')
    else:
        # For non-hardened derivation, we use the public key of the parent
        priv_key = SigningKey.from_string(key, curve=SECP256k1)
        pub_key = priv_key.get_verifying_key().to_string(encoding='compressed')
        data = pub_key + index.to_bytes(4, 'big')

    # Perform HMAC-SHA512 to derive the child key and chain code
    I = hashlib.hmac.new(chaincode, digestmod=hashlib.sha512).update(data).digest()
    
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
