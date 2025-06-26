import hashlib
import math

#####################################RSA Functions###################################### 
def is_prime(num):      # Check if a number is prime
    if num < 2:
        return False
    for i in range(2, int(math.sqrt(num)) + 1): 
        if num % i == 0:
            return False
    return True

# -----------------------------------------------------------------------------
def extended_euclidean(a, b):       # Extended Euclidean Algorithm
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t

# -----------------------------------------------------------------------------------------
def mod_inverse(e, phi):        # Calculate modular inverse using Extended Euclidean Algorithm
    gcd, x, _ = extended_euclidean(e, phi)
    if gcd != 1:
        raise Exception("No modular inverse exists")
    return x % phi      # Ensure the result is positive

# ---------------------------------------------------------------------------------
def square_and_multiply(a, exponent, modulus):      # Square and Multiply algorithm for modular exponentiation
    y = 1
    binary = bin(exponent)[2:][::-1] # Convert to binary and reverse it for easier processing   

    for i in range(len(binary)):    
        if binary[i] == '1':        # If the bit is 1, multiply the current result by a
            y = (a * y) % modulus
        if i != len(binary) - 1:    # Avoid squaring on the last iteration
            a = (a * a) % modulus   
    return y

# -------------------------------------------------------------------------------------
def RSA_Key_Generation(p, q, e):                # Generate RSA keys
    if not (is_prime(p) and is_prime(q) and p != q):
        raise ValueError("p and q must be distinct primes")

    n = p * q
    phi = (p - 1) * (q - 1)

    if e <= 1 or e >= phi or extended_euclidean(e, phi)[0] != 1:    
        raise ValueError("must be e > 1 , e < φ(n), and e coprime to φ(n)")

    d = mod_inverse(e, phi)

    return (e, n), d, n

# ----------------------------------------------------------------------------------
def sign_message(message_hash, d, n):           # Sign a message using RSA private key
    return square_and_multiply(message_hash, d, n)

# ----------------------------------------------------------------------------------
def verify_signature(signature, original_hash, e, n):       # Verify a signature using RSA public key
    recovered_hash = square_and_multiply(signature, e, n) 
    if  recovered_hash == original_hash:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")

####################################### DES Functions ###########################################

def permute(block, table):      
    return ''.join(block[i - 1] for i in table)
# -----------------------------------------------------------------------------

def left_shift(bits, n):
    return bits[n:] + bits[:n]
# -----------------------------------------------------------------------------

def xor(a, b):
    return ''.join('0' if x == y else '1' for x, y in zip(a, b))


parity_bit_drop_table = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
]

key_compression_table = [       
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
]

shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# -----------------------------------------------------------------------------
def generate_round_keys(key_64bit):
    key_56bit = permute(key_64bit, parity_bit_drop_table)
    left, right = key_56bit[:28], key_56bit[28:]
    round_keys = []     
    for shift in shift_table:
        left = left_shift(left, shift)
        right = left_shift(right, shift)
        combined = left + right             # 56 bit key
        round_key = permute(combined, key_compression_table)    # 48 bit key
        round_keys.append(round_key)
    return round_keys

S_BOXES = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

# -----------------------------------------------------------------------------
def sbox_substitution(xor_result):
    output = ''
    for i in range(8):      # Splits it into 8 blocks of 6 bits each.
        block = xor_result[i * 6:(i + 1) * 6]       # Each block is processed through a different S-Box.
        row = int(block[0] + block[5], 2)           # The first and last bits of the block determine the row in the S-Box.
        col = int(block[1:5], 2)                    # The middle four bits determine the column in the S-Box.   
        val = S_BOXES[i][row][col]                  # The value from the S-Box is retrieved.
        output += f'{val:04b}'                      # The value is converted to a 4-bit binary string and appended to the output.
    return output

Expansion_P_box = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29,
    30, 31, 32, 1
]

Straight_permutation = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
]

# -----------------------------------------------------------------------------
def feistel(right, round_key):
    expanded = permute(right, Expansion_P_box)      # Expand the right half to 48 bits using the expansion permutation.
    xored = xor(expanded, round_key)                # XOR the expanded right half with the round key.
    sboxed = sbox_substitution(xored)               # Apply S-Box substitution to the XORed result.
    return permute(sboxed, Straight_permutation)    # Permute the S-Box output using the straight permutation to get a 32-bit output.

# -----------------------------------------------------------------------------

Initial_permutation = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
]

Final_permutation = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
]

# -----------------------------------------------------------------------------
def des_encrypt(plain_bin, round_keys):                 # Takes a 64-bit binary string and a list of round keys 48 bits each
    permuted = permute(plain_bin, Initial_permutation)
    left, right = permuted[:32], permuted[32:]
    for i in range(16):
        new_right = xor(left, feistel(right, round_keys[i])) # Apply first Feistel function to the right half and XOR the result with the left half, to produce the new right half.
        left = right            # Moves the old right half to become the new left half in the next round.
        right = new_right       # Updates the right half to the new value.
    combined = right + left         # ensure to delete the last swap.
    return permute(combined, Final_permutation)

# -----------------------------------------------------------------------------

def des_decrypt(cipher_bin, round_keys):
    permuted = permute(cipher_bin, Initial_permutation)
    left, right = permuted[:32], permuted[32:]
    for i in range(16):
        new_right = xor(left, feistel(right, round_keys[15 - i])) # Apply Feistel function to the right half using the round key in reverse order and XOR the result with the left half, to produce the new right half.
        left = right
        right = new_right
    combined = right + left
    return permute(combined, Final_permutation)
# -----------------------------------------------------------------------------

def hex_to_bin(hex_str):
    if hex_str.startswith('0x') or hex_str.startswith('0X'):
        hex_str = hex_str[2:]
    return f"{int(hex_str, 16):064b}"       # Converts a hexadecimal string to a 64-bit binary string, padding with leading zeros if necessary.

# -----------------------------------------------------------------------------

def bin_to_hex(bin_str):
    return f"0x{int(bin_str, 2):016X}"      # Converts a 64-bit binary string to a hexadecimal string, ensuring it is 16 characters long and prefixed with '0x'.

# -----------------------------------------------------------------------------

############################## Text to Binary and Binary to Text Conversion ########################################
def text_to_bin(text):          
    binary = ''.join(format(ord(c), '08b') for c in text)       #Converts each character in the text into its ASCII binary representation, padded to 8 bits.
    if len(binary) < 64:
        binary = binary + '0' * (64 - len(binary))  # padding with zeros.
    elif len(binary) > 64:          # If the binary string is longer than 64 bits, it truncates it to 64 bits.
        binary = binary[:64]        # ensures only 1 DES block (64 bits) is returned.        
    return binary

# -----------------------------------------------------------------------------
def bin_to_text(binary):
    text = ''
    for i in range(0, len(binary), 8):      # Loops over the binary string in chunks of 8 bits 
        byte = binary[i:i+8]                # Takes an 8-bit chunk from position i to i+8
        if len(byte) == 8:                  
            char_code = int(byte, 2)        # Converts the 8-bit binary chunk to an integer
            if char_code != 0:              # If the character code is not zero, it converts it to a character
                text += chr(char_code)      # Converts the ASCII code to a character and appends it to the result.
    return text

###################################### Main Function ########################################
def main():
    print("=== E-Voting System ===")
    candidate = input("Enter the name of the candidate: ").strip()
    mode = input("Select mode (1: Confidentiality / 2: Authentication / 3: Both): ").strip()
    
    # RSA inputs
    p = int(input("Enter prime p: "))
    q = int(input("Enter prime q: "))
    e = int(input("Enter public exponent e: "))
    
    # DES key input
    des_key = input("Enter a 16-character hex shared secret key (e.g., 133457799BBCDFF1): ").strip().upper()
    if len(des_key) != 16 or not all(c in "0123456789ABCDEF" for c in des_key):
        raise ValueError("Key must be a 16-character hexadecimal string.")
    
    # Generate RSA keys
    try:
        public_key, private_key, n = RSA_Key_Generation(p, q, e)
    except ValueError as err:
        print(f"Error: {err}")
        return
    
    e, n = public_key
    d = private_key
    
    # Generate DES round keys
    try:
        round_keys = generate_round_keys(hex_to_bin(des_key)) 
    except ValueError:
        print("Error: Invalid DES key format")
        return
    
    # Display parameters
    print("\n=== Key Parameters ===")
    print(f"RSA p: {p}")
    print(f"RSA q: {q}")
    print(f"RSA e: {e}")
    print(f"RSA d: {d}")
    print(f"RSA n: {n}")
    print(f"DES Key: {des_key}")
    
    # Convert candidate name to binary for DES
    message_bin = text_to_bin(candidate)
    
    # Process based on mode
    if mode == '1':
        print("\n=== Confidentiality Mode ===")
        cipher_bin = des_encrypt(message_bin, round_keys)
        cipher_hex = bin_to_hex(cipher_bin)
        print(f"Encrypted Vote (hex): {cipher_hex}")
        decrypted_bin = des_decrypt(cipher_bin, round_keys)
        decrypted_text = bin_to_text(decrypted_bin)
        print(f"Decrypted Vote: {decrypted_text}")
        
    elif mode == '2':
        print("\n=== Authentication Mode ===")
        # Hash the vote message using SHA-256
        vote_bytes = candidate.encode() # Convert candidate name to bytes
        hash_bytes = hashlib.sha256(vote_bytes).digest()    # Convert to bytes
        hash_int = int.from_bytes(hash_bytes, byteorder='big') % n     # Convert to integer and % n ensures that the hash integer is within the valid range for RSA math.
        signature = sign_message(hash_int, d, n)
        print(f"Digital Signature: {signature}")
        verify_signature(signature, hash_int, e, n)
        
    elif mode == '3':
        print("\n=== Confidentiality & Authentication Mode ===")
        cipher_bin = des_encrypt(message_bin, round_keys)
        cipher_hex = bin_to_hex(cipher_bin)
        print(f"Encrypted Vote (hex): {cipher_hex}")
        # Hash the vote message using SHA-256
        vote_bytes = candidate.encode()
        hash_bytes = hashlib.sha256(vote_bytes).digest()
        hash_int = int.from_bytes(hash_bytes, byteorder='big') % n
        signature = sign_message(hash_int, d, n)
        print(f"Digital Signature: {signature}")
        decrypted_bin = des_decrypt(cipher_bin, round_keys)
        decrypted_text = bin_to_text(decrypted_bin)
        print(f"Decrypted Vote: {decrypted_text}")
        verify_signature(signature, hash_int, e, n)
        
    else:
        print("Invalid mode selected. Exiting.")

if __name__ == "__main__":
    main()