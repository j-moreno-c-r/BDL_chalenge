import hashlib
from tools import hashdouble
def merkleroot(txids):
    # Exit Condition: Stop recursion when we have one hash result left
    if len(txids) == 1:
        # Convert the result to a string and return it
        return txids[0]
    
    # Keep an array of results
    result = []

    # 1. Split up array of hashes into pairs
    for i in range(0, len(txids), 2):
        one = txids[i]
        two = txids[i + 1] if i + 1 < len(txids) else one  
        concat = one + two

        # 3. Hash the concatenated pair and add to results array
        result.append(hashdouble(concat))

    # Recursion: Do the same thing again for these results
    return merkleroot(result)
