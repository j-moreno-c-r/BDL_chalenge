import struct
import  hashlib

def field(data, size):
    """Convert a number to a hex string with leading zeros to fit a specific byte size"""
    value = int(data)
    hex_str = format(value, '0{}x'.format(size * 2))
    return hex_str

# Hash function used in the merkle root function (and in Bitcoin in general)
def hashdouble(hex_str):
    # Convert hex string to binary data
    binary = bytes.fromhex(hex_str)
    # First SHA-256 hash
    doublehash = hashlib.sha256( hashlib.sha256(binary).digest()).digest()
    return doublehash.hex()


def reversebytes(data):
    """Reverse the order of bytes (hex string)"""
    bytes_list = [data[i:i+2] for i in range(0, len(data), 2)]
    reversed_bytes = bytes_list[::-1]
    return ''.join(reversed_bytes)

def decode_varint(stream):
    n = stream[0]
    if n < 0xFD:
        return n, 1
    elif n == 0xFD:
        return struct.unpack("<H", stream[1:3])[0], 3
    elif n == 0xFE:
        return struct.unpack("<I", stream[1:5])[0], 5
    elif n == 0xFF:
        return struct.unpack("<Q", stream[1:9])[0], 9

def deserialize_tx(serialized_tx):
    offset = 0
    
    version = struct.unpack("<L", serialized_tx[offset:offset+4])[0]
    offset += 4
    
    vin_count, vin_offset = decode_varint(serialized_tx[offset:])
    offset += vin_offset
    vin = []
    for _ in range(vin_count):
        txid = serialized_tx[offset:offset+32][::-1].hex()
        offset += 32
        vout = struct.unpack("<L", serialized_tx[offset:offset+4])[0]
        offset += 4
        script_length, script_offset = decode_varint(serialized_tx[offset:])
        offset += script_offset
        scriptsig = serialized_tx[offset:offset+script_length].hex()
        offset += script_length
        sequence = struct.unpack("<L", serialized_tx[offset:offset+4])[0]
        offset += 4
        vin.append({"txid": txid, "vout": vout, "scriptsig": scriptsig, 
                    "sequence": sequence})
    
    vout_count, vout_offset = decode_varint(serialized_tx[offset:])
    offset += vout_offset
    vout = []
    for _ in range(vout_count):
        value = struct.unpack("<Q", serialized_tx[offset:offset+8])[0]
        offset += 8
        script_length, script_offset = decode_varint(serialized_tx[offset:])
        offset += script_offset
        scriptpubkey = serialized_tx[offset:offset+script_length].hex()
        offset += script_length
        vout.append({"value": value, "scriptpubkey": scriptpubkey})
    
    locktime = struct.unpack("<L", serialized_tx[offset:offset+4])[0]
    
    return {
        "version": version,
        "vin": vin,
        "vout": vout,
        "locktime": locktime
    }

def decode_transaction(raw_transaction):
    transaction = deserialize_tx(bytes.fromhex(raw_transaction))
    version = "Version:", transaction["version"]
    for inp in transaction["vin"]:
        txid = reversebytes(inp["txid"])
        vout = inp["vout"]
        scriptsig = inp["scriptsig"]
        sequence = inp["sequence"]
    for out in transaction["vout"]:
        value = out["value"]
        scriptpubkey = out["scriptpubkey"]
    locktime =  transaction["locktime"]
    tx_decode = {
        "version": version,
        "vin": {
            "txid" : txid,
            "vout" : vout,
            "scriptsig" : scriptsig,
            "sequence" : sequence,
        },
        "vout": {
            "value" : value,
            "scriptpubkey" : scriptpubkey,
        "locktime":locktime,
        }
    }
    #print(tx_decode)
    return tx_decode
