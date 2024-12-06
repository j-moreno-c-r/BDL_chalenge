import json
from base58 import base58_decode
from getpubfrompriv import priv_for_pub
from deserialize_key import deserialize_in_json
from priv_child import derive_priv_child
from childs_priv_keys import get_wallet_privs
#wpkh(tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9/84h/1h/0h/0/*)#uadxj6umj


BIP32_HARDENED = 0x80000000
SECP256K1_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)
SECP256K1_G = int('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16)

if __name__ == "__main__":
    all_bytes=base58_decode("tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9")
    #print(len(all_bytes))
    json_desereliazed = deserialize_in_json(all_bytes)
    main_dict = json.loads(json_desereliazed)

    #print(deserialize_in_json(all_bytes))
    important_bytes=all_bytes[13:45]

    #print(len(important_bytes))
    compressed_pub = priv_for_pub(important_bytes)
    #print(compressed_pub.hex())
    
    parent_private_key = bytes.fromhex(main_dict["key_data"]) 
    parent_chain_code = bytes.fromhex(main_dict["chain_code"])
    #print(derive_priv_child(parent_private_key,parent_chain_code,index=0,hardened=True))
    
    
    derivation_path = [
        (84 | BIP32_HARDENED, True),
        (0 | BIP32_HARDENED, True),
        (0 | BIP32_HARDENED, True)
    ]

    print(get_wallet_privs(parent_private_key,parent_chain_code,derivation_path))



    

