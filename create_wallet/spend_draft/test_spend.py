import hashlib
from ecdsa import SigningKey, SECP256k1, util, VerifyingKey, ellipticcurve
import json
from typing import List
from spend import input_from_utxo, state_recovered_by_file,output_from_options, create_multisig_script, get_p2wpkh_scriptcode,get_commitment_hash,get_p2wsh_program,derive_pubkey


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


state = state_recovered_by_file
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
# Fetch the private key we need to sign with
priv_to_sign = (bytes.fromhex(state["privs"][0]))
# Sign!
print(f"priv= {priv_to_sign.hex()}")
print(f"message = {message.hex()}")
signatured = sign(priv_to_sign,message)
print(f"publickey= {derive_pubkey(priv_to_sign).hex()}")
print(f"signature= {signatured.hex()}")
signature_decimal = str(int(signatured.hex(),16))
print(len(signature_decimal))
print(f"signature in decimal {signature_decimal}")