def recover_wallet_state(tprv: str):
    # Generate all the keypairs and witness programs to search for
    all_bytes=base58_decode("tprv8ZgxMBicQKsPdUpU7MYiBXtJ2Ss5h2hCjgra8YqdR1dvMWTCMHRmEtUVxp3GGKofZ6zAZNU1E5CkAB2P1QXFECC4QMsUDR1Gpe8zBXdWJm9")
    json_desereliazed = deserialize_key(all_bytes)
    main_dict = json.loads(json_desereliazed)
    parent_private_key = bytes.fromhex(main_dict["key_data"]) 
    parent_chain_code = bytes.fromhex(main_dict["chain_code"])
    derivation_path = [
        (84 | BIP32_HARDENED, True),
        (0 | BIP32_HARDENED, True),
        (0 | BIP32_HARDENED, True)
    ]

    privs = get_wallet_privs(parent_private_key,parent_chain_code,derivation_path)
    pubs = []
    for c in privs:
        pubs+=get_pub_from_priv(c) 
        
    programs = []
    for d in pubs:
        programs+=get_p2wpkh_program(d)

    # Prepare a wallet state data structure
    state = {
        "utxo": {},
        "balance": 0,
        "privs": privs,
        "pubs": pubs,
        "programs": programs
    }

    # Scan blocks 0-310
    height = 310
    for h in range(height + 1):
        block_information = bcli(f"getblock{bcli(f"getblockhash{h}")}")
        location_tx_jq = '.tx[].txid'
        txs = jq.one(location_tx_jq, block_information)
        # Scan every tx in every block
        for tx in txs:
            transaction_information = bcli(f"decoderawtransaction{bcli(f"getrawtransaction{tx}")}")
            # Check every tx input (witness) for our own compressed public keys.
            # These are coins we have spent.
            for inp in tx["vin"]:
                  
                    # Remove this coin from our wallet state utxo pool
                    # so we don't double spend it later

            # Check every tx output for our own witness programs.
            # These are coins we have received.
            for out in tx["vout"]:
                    # Add to our total balance

                    # Keep track of this UTXO by its outpoint in case we spend it later

    return state


if __name__ == "__main__":
    print(f"{WALLET_NAME} {recover_wallet_state(EXTENDED_PRIVATE_KEY)['balance']}")