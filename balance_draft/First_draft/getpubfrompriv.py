import ecdsa
from ecdsa import SECP256k1

def priv_for_pub(b: bytes) -> bytes:
    # Ensure the byte array is 32 bytes long (256 bits)
    if len(b) != 32:
        raise ValueError("Private key must be 32 bytes long")
    
    # Create a private key object using the secp256k1 curve
    sk = ecdsa.SigningKey.from_string(b, curve=SECP256k1)
    
    # Get the corresponding public key
    vk = sk.get_verifying_key()
    
    # Get the compressed public key
    compressed_public_key = vk.to_string(encoding='compressed')
    
    return compressed_public_key


