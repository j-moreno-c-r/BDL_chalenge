import json
from base58 import base58_decode
from getpubfrompriv import priv_for_pub
from deserialize_key import deserialize_in_json
from priv_child import derive_priv_child

if __name__ == "__main__":
    all_bytes=base58_decode("tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9")
    #print(len(all_bytes))
    json_desereliazed = deserialize_in_json(all_bytes)
    main_dict = json.loads(json_desereliazed)

    print(deserialize_in_json(all_bytes))
    important_bytes=all_bytes[13:45]

    #print(len(important_bytes))
    compressed_pub = priv_for_pub(important_bytes)
    print(compressed_pub.hex())
    parent_private_key = bytes.fromhex(main_dict["key_data"]) 
    parent_chain_code = bytes.fromhex(main_dict["chain_code"])
    print(derive_priv_child(parent_private_key,parent_chain_code,index=0,hardened=True))

    

