

import hashlib



#NATIVE INT CAST TO BE
STATIC_BLOCK_DATA = {
    "bits" : "ae77031e",
    "prev_block_hash" : "000000002a22cfee1f2c846adbd12b3e183d4f97683f85dad08a79780a84bd55",
    "version" : int(1).to_bytes(4, byteorder='little').hex(),
    "time" : int(1231731025).to_bytes(4, byteorder='little').hex(),
    "transactions": ["01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0102ffffffff0100f2052a01000000434104d46c4968bde02899d2aa0963367c7a6ce34eec332b32e42e5f3407e052d64ac625da6f0718e7b302140434bd725706957c092db53805b821a85b23a7ac61725bac00000000", "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"]
}

def reversebytes(data: bytes):
    bytes_list = [data[i:i+2] for i in range(0, len(data), 2)]
    reversed_bytes = bytes_list[::-1]
    str_bytes = []
    for b in reversed_bytes:
        str_bytes.append(b.hex())
    return ''.join(str_bytes)


def hash256(item: str):
    return hashlib.sha256(hashlib.sha256(bytes.fromhex(item)).digest()).digest()

def calculate_merkle_root(transactions: list):
    return hash256(transactions[0] + transactions[1]).hex()

# from the STATIC_BLOCK_DATA, returns a `partial_header` and `nonce` touple.
def build_header_template():

    header_list = [STATIC_BLOCK_DATA["version"], STATIC_BLOCK_DATA["prev_block_hash"], calculate_merkle_root(STATIC_BLOCK_DATA["transactions"]), STATIC_BLOCK_DATA["time"], STATIC_BLOCK_DATA["bits"]]

    ret = "".join(header_list)

    return ret, 0

def mine():
    header, nonce = build_header_template()
    while True:
        header = "".join([header , int(nonce).to_bytes(4, byteorder='little').hex()])
        result = hash256(header)
        print(result.hex())
        if int(reversebytes(result), 32) <= int("00000377ae000000000000000000000000000000000000000000000000000000", 32):
            print("yay, block found")
            print(f"block hash {reversebytes(result)}")
            print(f"block_header {header}")
            break
        if nonce == 4294967295:
            print("Block not found on nonce spam")
            break
        nonce += 1

mine()
