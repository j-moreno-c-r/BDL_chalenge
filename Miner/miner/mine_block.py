import os
from hashlib import sha256
from merkle_tree import merkleroot
from PoW import mining
from create_block_things import create_block_header, create_block
from tools import decode_transaction, hashdouble
#from PoW import Block 
#create merkle tree
# Test (e.g. block 000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506)

folder_path = '../../data'  # Replace with your folder path
file_list = []
for entry in os.listdir(folder_path):
    full_path = os.path.join(folder_path, entry)
    if os.path.isfile(full_path):
        file_list.append(full_path)  # Use `entry` for filenames only
raw_transaction = []
for c in file_list:
    with open(f'{c}') as f: s = f.read()
    raw_transaction.append(s)
# a list of dicts 🤣
txs_deserialized = []
for c in raw_transaction:
    d = decode_transaction(c)
    txs_deserialized.append(d)
#print(txs_deserialized)

txids_list= [] 
for s in txs_deserialized:
    version = f"{s["version"]}"# chalenge 
    inputs = ""
    for c in s["vin"]:
        inputs += c
    outputs = ""
    for c in s["vout"]:
        outputs += c
    locktime = f"{s["vout"]["locktime"]}"
    txids_list.append(hashdouble((version+inputs+outputs+locktime).encode("utf-8").hex()))

# TXIDs must be in natural byte order when creating the merkle root
txids = [''.join([x[i:i+2] for i in range(0, len(x), 2)][::-1]) for x in txids_list]

# Create the merkle root
result = merkleroot(txids)
timed = '1231731025'# equivalente a 0x496ab951 : https://www.epochconverter.com/hex?q=496ab951 
# Display the result in reverse byte order
merkleroot_final = ''.join([result[i:i+2] for i in range(0, len(result), 2)][::-1])

data_header = {"dificult": "0xae77031e",
    "version" :  '1',
    "prev_block" : "00000000000000000006a4a234288a44e715275f1775b77b2fddb6c02eb6b72f",
    "merkleroot": merkleroot_final,
    "time" :  timed}
header,bits= create_block_header(data_header["dificult"], 
                                data_header["version"],
                                data_header["prev_block"],
                                data_header["merkleroot"],
                                data_header["time"],
)
blockhash, nonce = mining(header,0,bits)
block = create_block(data_header,nonce,bits,raw_transaction)
print(blockhash)
#the full block
print(block)
