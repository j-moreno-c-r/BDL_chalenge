
import ecdsa
import hashlib
import base58

EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9"
#needs to do the derivation process to find childs first


stringb58_integer = base58.b58encode_check(f"{EXTENDED_PRIVATE_KEY}")

# These are the 3 private keys in base58check encoding.
privkey_b58_1 = EXTENDED_PRIVATE_KEY


# Remove the \x80 version prefix and x\01 compression suffix.
bytes = base58.b58decode_check(privkey_b58_1.encode())
privkey_bin_1 = bytes[0:32]

# Create signing keys using the SECP256k1 curve in ECDSA.
sk_bin_1 = ecdsa.SigningKey.from_string(privkey_bin_1, ecdsa.SECP256k1)


# Derive verifying keys from the signing keys.
vk_bin_1 = sk_bin_1.verifying_key.to_string()


# Determine if the Y value is even. This is required for compression.
vk_iseven_1 = int(vk_bin_1.hex(), base=16) % 2 == 0


# Determine the prefix for the X value based on whether the Y value is even.
vk_prefix_1 = b"\x02" if vk_iseven_1 else b"\x03"


# Extract the X value from the verifying key. X is the first 32 bytes.
vk_xval_1 = vk_bin_1[:32]

# Get the SHA256 hash of the X value with the even/odd prefix.
vk_sha256_1 = hashlib.sha256(vk_prefix_1 + vk_xval_1).digest()


# Get the RIPEMD-160 hash of the SHA256 hash, then add the address prefix.
ripemd160_1 = hashlib.new("ripemd160")
ripemd160_1.update(vk_sha256_1)
address_1 = b"\x00" + ripemd160_1.digest()



# Get the base58check encoding for each address.
address_b58_1 = base58.b58encode_check(address_1)


# Show the addresses.
for x in [address_b58_1]:
    print(x.decode())

