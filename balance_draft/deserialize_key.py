
# Deserialize the extended key bytes and return a JSON object
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)

import json

def deserialize_in_json(bytes):
    # Slice the bytes for each component
    version = bytes[0:4]
    depth = bytes[4:5]
    fingerprint = bytes[5:9]
    child_number = bytes[9:13]
    chain_code = bytes[13:45]
    key_data = bytes[45:78]
    checksum = bytes[78:82]

    # Convert each component to hexadecimal strings
    private_key_hex = bytes.hex()
    version_hex = version.hex()
    depth_hex = depth.hex()
    fingerprint_hex = fingerprint.hex()
    child_number_hex = child_number.hex()
    chain_code_hex = chain_code.hex()
    key_data_hex = key_data.hex()
    checksum_hex = checksum.hex()

    # Create a JSON object
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

    # Print the JSON object
    return json.dumps(json_object, indent=4)
