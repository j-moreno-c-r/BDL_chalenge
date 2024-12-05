def base58_decode(base58_string: str) -> bytes:
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    
    # Convert Base58 string to a big integer
    num = 0
    
    for c in base58_string:
        num *= 58
        num += base58_alphabet.find(c)
    
    # Convert the number to bytes
    # Calculate the length of the resulting byte array
    pad = len(base58_string) - len(base58_string.lstrip('1'))
    result_bytes = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    
    # Add padding for leading '1's in the Base58 string
    return b'\x00' * pad + result_bytes

# Example usage
"""base58_string = "tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9"
decoded_bytes = base58_decode(base58_string)
tamanho= len(decoded_bytes)
print(tamanho)
print(decoded_bytes)"""
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