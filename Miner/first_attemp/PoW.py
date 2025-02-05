import hashlib 
from tools import reversebytes, hashdouble, field

def calculate_hash(self): 
    """ 
    Calculates the SHA-256 hash of the 
    block's data, previous hash, and nonce. 
    """
    sha = hashlib.sha256() 
    sha.update(str(self.data).encode('utf-8') +
            str(self.previous_hash).encode('utf-8') +
            str(self.nonce).encode('utf-8')) 
    return sha.hexdigest() 

# Mine!

def mining(header, nonce, bits):
    while True:
        # Construct the block header with the current nonce
        nonce_field = field(nonce, 4)
        reversed_nonce = reversebytes(nonce_field)
        attempt = header + reversed_nonce
        
        # Calculate the hash
        result_hex = hashdouble(attempt)
        reversed_result = reversebytes(result_hex)
        result_int = int(reversed_result, 16)
        
        print(f"{nonce}: {reversed_result}")
        
        # Check if the result is below the target
        if result_int < bits:
            break
        if nonce == 4294967295:
            print("deu merda")
            break
        nonce += 1
    return reversed_result, nonce

