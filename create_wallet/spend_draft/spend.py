import hashlib
from ecdsa import SigningKey, SECP256k1, util, VerifyingKey, ellipticcurve
import json
from typing import List
"""from balance import (
    EXTENDED_PRIVATE_KEY,
    bcli,
    get_p2wpkh_program,
    derive_pubkey)"""
#adaptar para get pub from priv✅
def derive_pubkey(private_key: bytes) -> bytes:
    """
    Derive the compressed public key from a private key.
    """
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    vk = sk.verifying_key
    x, y = vk.pubkey.point.x(), vk.pubkey.point.y()
    compressed_pubkey = (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')
    return compressed_pubkey
#auxiliars
def var_int(n: int) -> bytes:
    """Convert an integer to a Bitcoin variable length integer."""
    if n < 0xFD:
        return n.to_bytes(1, "little")
    elif n <= 0xFFFF:
        return b'\xfd' + n.to_bytes(2, "little")
    elif n <= 0xFFFFFFFF:
        return b'\xfe' + n.to_bytes(4, "little")
    else:
        return b'\xff' + n.to_bytes(8, "little")

#❗= in the test file but not totally works
# from the first two keys of the list of 2000 
# Given 2 compressed public keys as byte arrays, construct
# a 2-of-2 multisig output script. No length byte prefix is necessary.✅
def create_multisig_script(keys: List[bytes]) -> bytes:
    Opcode_list = b"".join([bytes([0x21])+ k for k in keys])
    multisig_script = bytes([0x52]) + Opcode_list + bytes([0x52, 0xae])
    return multisig_script

# Given an output script as a byte array, compute the p2wsh witness program
# This is a segwit version 0 pay-to-script-hash witness program.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wsh❗
def get_p2wsh_program(script: bytes,siganture, version: int = 0) -> bytes:
    sha256_hash = hashlib.sha256(siganture + script).digest()
    witness_program = version.to_bytes() + bytes([0x0020]) + sha256_hash
    
    return witness_program

# Given an outpoint, return a serialized transaction input spending it
# Use hard-coded defaults for sequence and scriptSig❗  
def input_from_utxo(txid: bytes, index: int) -> bytes:
    # Hard-coded defaults
    sequence = 0xFFFFFFFF  # Default sequence value
    scriptSig_default = b'\x76\xa9\x14' + b'\x20' + b'\x88\xac'  # Example P2PKH scriptSig

    # Serialize the outpoint (txid and index)
    serialized_input = txid[::-1]  # Reverse the byte order for little-endian
    serialized_input += index.to_bytes(4, 'little')

    # Add the length of the scriptSig (varint format)
    if len(scriptSig_default) < 0xFD:
        serialized_input += len(scriptSig_default).to_bytes(1, 'little')
    else:
        raise ValueError("ScriptSig too long for varint encoding")

    # Serialize the scriptSig
    serialized_input += scriptSig_default

    # Add the sequence number
    serialized_input += sequence.to_bytes(4, 'little')
    return serialized_input
# Given an output script and value (in satoshis), return a serialized transaction output❗
def output_from_options(script: bytes, value: int) -> bytes:
    # Convert the value from satoshis to little-endian 64-bit integer
    value_bytes = value.to_bytes(8, byteorder='little')
    
    # Calculate the length of the script in bytes
    script_len = len(script)
    
    # Serialize the script length using variable-length integer encoding
    if script_len < 0xFD:
        script_len_bytes = script_len.to_bytes(1, byteorder='little')
    elif script_len <= 0xFFFF:
        script_len_bytes = b'\xFD' + script_len.to_bytes(2, byteorder='little')
    elif script_len <= 0xFFFFFFFF:
        script_len_bytes = b'\xFE' + script_len.to_bytes(4, byteorder='little')
    else:
        script_len_bytes = b'\xFF' + script_len.to_bytes(8, byteorder='little')
    
    # Concatenate all parts to form the transaction output
    output = value_bytes + script_len_bytes + script
    
    return output

# Given a JSON utxo object, extract the public key hash from the output script
# and assemble the p2wpkh scriptcode as defined in BIP143
# <script length> OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification❗
def get_p2wpkh_scriptcode(utxo: dict) -> bytes:
    # Extract the public key hash from the output script
    pub_key_hash = utxo['address'][0][3:]
    
    # Define the standard p2wpkh script
    op_dup = b'\x76'  # OP_DUP
    op_hash160 = b'\xa9'  # OP_HASH160
    op_equalverify = b'\x88'  # OP_EQUALVERIFY
    op_checksig = b'\xac'  # OP_CHECKSIG
    
    # Assemble the scriptcode
    scriptcode = (
        op_dup +
        op_hash160 +
        pub_key_hash.encode('utf-8') +
        op_equalverify +
        op_checksig
    )
    return scriptcode
# Compute the commitment hash for a single input and return bytes to sign.
# This implements the BIP 143 transaction digest algorithm
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
# We assume only a single input and two outputs,
# as well as constant default values for sequence and locktime❗
def get_commitment_hash(outpoint: bytes, scriptcode: bytes, value: int, outputs: List[bytes]) -> bytes:
    def dsha256(data: bytes) -> bytes:
        first_rollet = hashlib.sha256(data).digest()
        return hashlib.sha256(first_rollet).digest()

    # Version
    version = b'\x01\x00\x00\x00'
    
    # All TX input outpoints (only one in our case)
    input_outpoints_hash = dsha256(outpoint)
    
    # All TX input sequences (only one for us, always default value 0xFFFFFFFF)
    sequence_hash = dsha256(b'\xFF\xFF\xFF\xFF')
    
    # Single outpoint being spent
    single_input = outpoint
    
    # Scriptcode (the scriptPubKey in/implied by the output being spent)
    script_code_hash = dsha256(scriptcode)
    
    # Value of output being spent
    value_bytes = int(value).to_bytes(8, byteorder='little')
    
    # Sequence of output being spent (always default for us 0xFFFFFFFF)
    sequence = b'\xFF\xFF\xFF\xFF'
    
    # All TX outputs
    output_hash = dsha256(b''.join(outputs))
    
    # Locktime (always default for us 0x00000000)
    locktime = b'\x00\x00\x00\x00'
    
    # SIGHASH_ALL (always default for us 0x01)
    sighash_type = b'\x01'
    
    # Concatenate all components
    data_to_hash = (
        version +
        input_outpoints_hash +
        sequence_hash +
        single_input +
        script_code_hash +
        value_bytes +
        sequence +
        output_hash +
        locktime +
        sighash_type
    )
    
    # Return the final hash
    return dsha256(data_to_hash)

# Given a JSON utxo object and a list of all of our wallet's witness programs,
# return the index of the derived key that can spend the coin.
# This index should match the corresponding private key in our wallet's list.❗
def get_key_index(utxo: object, programs: List[str]) -> int:
    # Extract public key or address from UTXO (this part depends on the structure of your UTXO)
    utxo_public_key = utxo['pubs']  # Example assuming 'public_key' is a field in UTXO
    
    # Iterate over the list of programs to find a match
    for index, program in enumerate(programs):
        if program == utxo_public_key:
            return index
    
    # If no match is found, raise an error or return -1
    raise ValueError("No matching witness program found for the UTXO")

# Given a private key and message digest as bytes, compute the ECDSA signature.
# Bitcoin signatures:
# - Must be strict-DER encoded
# - Must have the SIGHASH_ALL byte (0x01) appended
# - Must have a low s value as defined by BIP 62:
#   https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#user-content-Low_S_values_in_signatures ❗
def sign(priv: bytes, msg: bytes) -> bytes:
    # Keep signing until we produce a signature with "low s value"
    # We will have to decode the DER-encoded signature and extract the s value to check it
    # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    
    # Ensure the private key and message are in the correct format
    if len(priv) != 32 or len(msg) != 32:
        raise ValueError("Invalid input lengths. Both priv and msg must be 32 bytes.")
    
    # Initialize the ECDSA signing key with a private key
    priv_key = SigningKey.from_string(priv, curve=SECP256k1)
    
    # Sign the message digest
    signature = priv_key.sign(msg, hashfunc=hashlib.sha256)
    
    return signature

# Given a private key and transaction commitment hash to sign,
# compute the signature and assemble the serialized p2pkh witness
# as defined in BIP 141 (2 stack items: signature, compressed public key)
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification❗
def get_p2wpkh_witness(priv: bytes, msg: bytes) -> bytes:
    # Load the private key and create a signing key object
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    
    # Sign the message to get the DER signature
    der_signature = sign(priv,msg)
    
    # Recover the public key from the private key
    vk = sk.get_verifying_key()
    pubkey_derived = derive_pubkey(priv)
    
    # Serialize the public key in compressed format
    compressed_pubkey = b'\x02' + pubkey_derived if vk.pubkey.point.y() & 1 == 0 else b'\x03' + vk.pubkey.point.x()
    
    # Create the witness stack
    # The witness consists of two items: the signature and the compressed public key
    witness = b''.join([
        len(der_signature).to_bytes(1, 'little'),  # Length of the signature (varint)
        der_signature,                             # Signature in DER format
        len(compressed_pubkey).to_bytes(1, 'little'),  # Length of the compressed public key (varint)
        compressed_pubkey                          # Compressed public key
    ])
    
    return witness

# Given two private keys and a transaction commitment hash to sign,
# compute both signatures and assemble the serialized p2pkh witness
# as defined in BIP 141
# Remember to add a 0x00 byte as the first witness element for CHECKMULTISIG bug
# https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki❗
def get_p2wsh_witness(privs: List[bytes], msg: bytes) -> bytes:
    # Ensure we have exactly two private keys
    if len(privs) != 2:
        raise ValueError("Exactly two private keys are required for this function.")
    
    # Initialize the witness elements list with a 0x00 byte
    witness_elements = [b'\x00']
    
    # Sign the message with each private key and append the signatures to the witness elements
    for priv in privs:
        sk = SigningKey.from_string(priv, curve=SECP256k1)
        vk = sk.get_verifying_key()
        signature = sk.sign(msg, sigencode=lambda r, s: bytes([27 + 4]) + r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
        witness_elements.append(signature)
    
    # Serialize the witness elements into a single byte string
    serialized_witness = b''.join(witness_elements)
    
    return serialized_witness

# Given arrays of inputs, outputs, and witnesses, assemble the complete
# transaction and serialize it for broadcast. Return bytes as hex-encoded string
# suitable to broadcast with Bitcoin Core RPC.
# https://en.bitcoin.it/wiki/Protocol_documentation#tx✅
def assemble_transaction(inputs: List[bytes], outputs: List[bytes], witnesses: List[bytes]) -> str:
    # Transaction version (4 bytes, little-endian)
    version = (2).to_bytes(4, "little")
    # Witness marker and flag
    witness_flag = bytes.fromhex("0001")
    # Locktime (4 bytes, little-endian)
    locktime = bytes.fromhex("00000000")
    input_count = len(inputs).to_bytes(1, 'big')
    output_count = len(outputs).to_bytes(1, 'big')
    transaction = version + witness_flag
    transaction += input_count 
    for c in inputs:
        transaction += c
    transaction += output_count
    for d in outputs:
        transaction += d
    for h in witnesses:
        transaction += h
    transaction += locktime
    # Convert to hex-encoded string
    return transaction.hex()

# Given arrays of inputs and outputs (no witnesses!) compute the txid.
# Return the 32 byte txid as a *reversed* hex-encoded string.
# https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format❗
def get_txid(inputs: List[bytes], outputs: List[bytes]) -> str:
    version = (2).to_bytes(4, "little")
    locktime = bytes.fromhex("00000000")
        # Serialize the transaction inputs
    serialized_inputs = b""
    for txin in inputs:
        serialized_inputs += txin

    # Serialize the transaction outputs
    serialized_outputs = b""
    for txout in outputs:
        serialized_outputs += txout

    # Concatenate all parts to form the complete transaction serialization
    serialized_transaction = version + \
                            len(inputs).to_bytes(1, "little") + serialized_inputs + \
                            len(outputs).to_bytes(1, "little") + serialized_outputs + \
                            locktime

    # Compute the double SHA-256 hash
    sha256_hash = hashlib.sha256(serialized_transaction).digest()
    txid_hash = hashlib.sha256(sha256_hash).digest()

    # Reverse the byte order to get the txid in the correct format
    txid = bytes(reversed(txid_hash)).hex()

    return txid

# Spend a p2wpkh utxo to a 2 of 2 multisig p2wsh and return the txid
def spend_p2wpkh(state: object) -> str:
    FEE = 1000
    AMT = 1000000
    # Choose an unspent coin worth more than 0.01 BTC
    my_initial_utxo = state['utxo']['00147ae11d87fb7531679a6db04fa51250794c08c1b0'] 

    # Create the input from the utxo
    # Reverse the txid hash so it's little-endian
    input = input_from_utxo(bytes.fromhex(my_initial_utxo["txid"]),int(my_initial_utxo["vout"]))
    # Compute destination output script and output
    pubs_to_mult = []
    pubs_to_mult = []
    pubs_to_mult.append(bytes.fromhex(state["pubs"][0]))
    pubs_to_mult.append(bytes.fromhex(state["pubs"][1]))
    script_destination_output = create_multisig_script(pubs_to_mult)
    output_destination = output_from_options(script_destination_output,int(my_initial_utxo["amount"]))
    # Compute change output script and output
    script_change_output = get_p2wpkh_scriptcode(my_initial_utxo)
    output_change = output_from_options(script=script_change_output,value=int(my_initial_utxo["amount"]))
    # Get the message to sign
    outs = []
    outs.append(output_destination)
    outs.append(output_change)
    message = get_commitment_hash(input, script_destination_output, int(my_initial_utxo["amount"]), outs)
    print(f"message {(hashlib.sha256(message).digest()).hex()}")
    # Fetch the private key we need to sign with
    priv_to_sign = (bytes.fromhex(state["privs"][0]))
    # Sign!
    signatured = sign(priv_to_sign,message)
    print(f'private key: {priv_to_sign.hex()}')
    print(f'signature: {signatured.hex()}')
    # Assemble
    witness_to_assemble = []
    witness_to_assemble.append(get_p2wsh_program(script_destination_output,signatured))

    inputs_for_assemble = [] 
    inputs_for_assemble.append(input)
    outputs_for_assemble = []
    outputs_for_assemble.append(output_destination)
    outputs_for_assemble.append(output_change)
    final = assemble_transaction(inputs_for_assemble,outputs_for_assemble,witness_to_assemble)
    # Reserialize without witness data and double-SHA256 to get the txid
    txid = get_txid(inputs_for_assemble,outputs_for_assemble)
    # For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    return txid, final


# Spend a 2-of-2 multisig p2wsh utxo and return the txid
def spend_p2wsh(state: object, txid: str) -> str:
    COIN_VALUE = 1000000
    FEE = 1000
    AMT = 0
    # Create the input from the utxo
    # Reverse the txid hash so it's little-endian

    # Compute destination output script and output

    # Compute change output script and output

    # Get the message to sign

    # Sign!

    # Assemble

    # For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    finalhex = "0"
    return finalhex


# Recover wallet state: We will need all key pairs and unspent coins
#state = recover_wallet_state(EXTENDED_PRIVATE_KEY)
with open('utxo.txt') as f:
    state_recovered_by_file= json.load(f)
txid1, tx1 = spend_p2wpkh(state_recovered_by_file)
print(f"final: {tx1}")

print(f" txid:  {txid1}")
#tx2 = spend_p2wsh(state, txid1)
#print(tx2)
