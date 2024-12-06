import hashlib

def get_p2wpkh_program(pubkey: bytes, version: int = 0) -> bytes:
    # Step 1: Hash the compressed public key with SHA-256
    sha256_pubkey = hashlib.sha256(pubkey).digest()
    
    # Step 2: Hash the result with RIPEMD-160 to get the pubkeyhash
    ripemd160_pubkeyhash = hashlib.new('ripemd160', sha256_pubkey).digest()
    
    # Step 3: Construct the witness program
    # For p2wpkh, version 0 is represented as 0x00 followed by the length of the hash (0x14 for 20 bytes)
    witness_program = b'\x00\x14' + ripemd160_pubkeyhash
    
    return witness_program

# Example usage:
# Assuming `pubkey` is a compressed public key in bytes
# pubkey = b'your_compressed_public_key_here'
# p2wpkh_scriptPubKey = get_p2wpkh_program(pubkey)
