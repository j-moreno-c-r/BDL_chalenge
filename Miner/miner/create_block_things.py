from tools import reversebytes, field


def create_block_header(dificult,version,prevblock,merkleroot,time,):
    # Target
    #ffff001d 0000000000000000ffff000000000000000000000000 target dificult
    # Block Header Fields
    bits = int(dificult, 16)
    # Construct the header (without nonce)
    header = (
        reversebytes(field(version, 4)) +
        reversebytes(prevblock) +
        merkleroot +
        reversebytes(field(time, 4)) +
        reversebytes(str(bits)) 

        )
    return header, bits

    
def create_block(header, nonce, bits,transactions):
    version = int(header["version"]).to_bytes(4,"little").hex()
    transactions_to_sum = " "
    for c in transactions:
        transactions_to_sum += c
    return version + header["prev_block"] + header["merkleroot"] + header["time"] + str(bits) + str(nonce) +transactions_to_sum