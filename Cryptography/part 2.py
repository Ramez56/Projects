from PIL import Image
import os

##############################################DES key generation###############################################
def hex_to_binary(hex_key):
    binary_key = bin(int(hex_key, 16))[2:].zfill(64)
    return binary_key

def binary_to_hex(binary_key):
    hex_key = hex(int(binary_key, 2))[2:].upper().zfill(16)
    return hex_key

def parity_bit_drop(binary_key):
    parity_bit_drop_table = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    ]
    reduced_key = ''.join([binary_key[i - 1] for i in parity_bit_drop_table])
    return reduced_key

def split_key(reduced_key):        #Split the 56-bit key into two 28-bit halves
    left_half = reduced_key[:28]
    right_half = reduced_key[28:]
    return left_half, right_half

def left_circular_shift(half, shifts):          # Perform left circular shift on a 28-bit half
    return half[shifts:] + half[:shifts]

def compression_permutation(left, right):          # Apply the compression permutation to combine halves into a 48-bit key
    compression_table = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ]
    combined = left + right
    compressed_key = ''.join([combined[i - 1] for i in compression_table])
    return compressed_key

def generate_round_keys(hex_key):           # Generate 16 round keys from the given hexadecimal key
    binary_key = hex_to_binary(hex_key)
    reduced_key = parity_bit_drop(binary_key)
    left, right = split_key(reduced_key)
    shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    round_keys = []
    for shifts in shift_table:
        left = left_circular_shift(left, shifts)
        right = left_circular_shift(right, shifts)
        round_key = compression_permutation(left, right)
        round_keys.append(round_key)
    return round_keys

############################################DES key generation###############################################

############################################DES encryption #################################################

def initial_permutation(binary_text):       # apply the initial permutation to the binary text
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]
    permuted_text = ''.join([binary_text[i - 1] for i in IP])
    return permuted_text

def final_permutation(binary_text):      # apply the final permutation to the binary text       
    FP = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]
    permuted_text = ''.join([binary_text[i - 1] for i in FP])
    return permuted_text

def split_text(permuted_text):         # Split the permuted text into left and right halves         
    left_half = permuted_text[:32]
    right_half = permuted_text[32:]
    return left_half, right_half

def expand_half(right_half):                # Expand the right half from 32 bits to 48 bits using the expansion table
    expansion_table = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    ]
    expanded_half = ''.join([right_half[i - 1] for i in expansion_table])
    return expanded_half

def xor_bits(a, b):                         # Perform XOR operation on two binary strings of equal length
    return ''.join(['1' if a[i] != b[i] else '0' for i in range(len(a))])

def substitute(expanded_half):                                  # Substitute the 48-bit input using S-boxes to produce a 32-bit output
    sboxes = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]
    blocks = [expanded_half[i:i + 6] for i in range(0, 48, 6)]      # Split into 8 blocks of 6 bits each
    substituted = ""
    for i, block in enumerate(blocks):
        sbox = sboxes[i]
        row = int(block[0] + block[5], 2)   # Row is determined by the first and last bits
        col = int(block[1:5], 2)            # Column is determined by the middle 4 bits
        value = sbox[row][col]
        substituted += bin(value)[2:].zfill(4)
    return substituted

def straight_permutation(substituted):                                  # Apply the straight permutation to the substituted bits
    permutation_table = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    ]
    permuted_bits = ''.join([substituted[i - 1] for i in permutation_table])
    return permuted_bits

def des_round(left, right, round_key):                # Perform one round of DES encryption
    expanded_right = expand_half(right)
    xored = xor_bits(expanded_right, round_key)
    substituted = substitute(xored)
    permuted = straight_permutation(substituted)
    new_right = xor_bits(left, permuted)            # XORs with the left half → becomes the new right half.
    return right, new_right                 # The old right becomes the new left

def des_encrypt(plaintext, round_keys):         # Perform DES encryption on the plaintext using the round keys
    binary_plaintext = hex_to_binary(plaintext)
    initial_perm = initial_permutation(binary_plaintext)
    left, right = split_text(initial_perm)
    for round_key in round_keys:            
        left, right = des_round(left, right, round_key)         #Each call updates left and right as per round logic
    combined = right + left                         # the final swap
    encrypted_binary = final_permutation(combined)
    encrypted_hex = binary_to_hex(encrypted_binary)
    return encrypted_hex

def des_decrypt(ciphertext, round_keys):        # Perform DES decryption on the ciphertext using the round keys
    binary_ciphertext = hex_to_binary(ciphertext)
    initial_perm = initial_permutation(binary_ciphertext)
    left, right = split_text(initial_perm)
    for round_key in reversed(round_keys):
        left, right = des_round(left, right, round_key)
    combined = right + left
    decrypted_binary = final_permutation(combined)
    decrypted_hex = binary_to_hex(decrypted_binary)
    return decrypted_hex

#############################################DES encryption #################################################

def load_image(image_path):
    img = Image.open(image_path)
    return img

# Save the encrypted image back to a file
def save_image(data, mode, size, output_path):
    img = Image.frombytes(mode, size, data)
    img.save(output_path)

def encrypt_ecb_cts(image_data, key):
    round_keys = generate_round_keys(key)  # Generate DES round keys
    block_size = 8  # DES block size is 8 bytes
    
    # Split image data into 8-byte blocks
    blocks = [image_data[i:i + block_size] for i in range(0, len(image_data), block_size)]
    
    # Handle CTS for the last two blocks
    if len(blocks[-1]) < block_size:  # If the last block is smaller than 8 bytes
        ciphertext = b"".join(bytes.fromhex(des_encrypt(block.hex(), round_keys)) for block in blocks[:-2])  # Encrypt all blocks except the last two
        last_full_block = bytes.fromhex(des_encrypt(blocks[-2].hex(), round_keys))  # Encrypt the second-to-last block
        partial_block = blocks[-1] + last_full_block[len(blocks[-1]):]  # Merge last block with extra bytes from encrypted full block
        ciphertext += bytes.fromhex(des_encrypt(partial_block.hex(), round_keys))  # Encrypt the modified partial block
        ciphertext += last_full_block[:len(blocks[-1])]  # Append the extra bytes from last full block
    else:
        ciphertext = b"".join(bytes.fromhex(des_encrypt(block.hex(), round_keys)) for block in blocks)  # Encrypt normally if no partial block
    
    return ciphertext

def encrypt_cbc_cts(image_data, key, iv):
    round_keys = generate_round_keys(key)  # Generate DES round keys
    block_size = 8  # DES block size is 8 bytes
    prev_block = iv  # Initialization vector for CBC mode
    ciphertext = b""  # used to store binary data,
    
    # Split image data into 8-byte blocks
    blocks = [image_data[i:i + block_size] for i in range(0, len(image_data), block_size)]
    
    # Encrypt each block with CBC mode
    for i in range(len(blocks)):
        if i == len(blocks) - 1 and len(blocks[i]) < block_size:  # If last block is smaller than 8 bytes (CTS case)
            last_full_block = bytes.fromhex(des_encrypt(bytes(a ^ b for a, b in zip(blocks[i - 1], prev_block)).hex(), round_keys))  # Encrypt the second-to-last block
            partial_block = blocks[i] + last_full_block[len(blocks[i]):]  # Merge last block with extra bytes from encrypted full block
            encrypted_partial = bytes.fromhex(des_encrypt(bytes(a ^ b for a, b in zip(partial_block, prev_block)).hex(), round_keys))  # Encrypt modified last block
            ciphertext += encrypted_partial  # Append encrypted last block
            ciphertext += last_full_block[:len(blocks[i])]  # Append stolen bytes from full block
        else:
            xored_block = bytes(a ^ b for a, b in zip(blocks[i], prev_block))  # XOR plaintext with previous ciphertext block (or IV for the first block)
            encrypted_block = bytes.fromhex(des_encrypt(xored_block.hex(), round_keys))  # Encrypt the XORed block
            ciphertext += encrypted_block  # Append encrypted block to ciphertext
            prev_block = encrypted_block  # Update chaining value for next round
    
    return ciphertext

def main():
    try:
        # Get image path from user input
        image_path = input("Enter the path to the image file: ").strip()
        
        # Get encryption key from user input
        key = input("Enter a 16-character hexadecimal DES key: ").strip().upper()
        
        # Validate the key length
        if len(key) != 16 or not all(c in '0123456789ABCDEF' for c in key):
            raise ValueError("Invalid key. It must be a 16-character hexadecimal string.")
        
        # File paths for output
        ecb_output = r"C:\Users\User\Documents\courses_slides\Cryptography\Final_code _3\ecb_encrypted_cts.jpg"
        cbc_output = r"C:\Users\User\Documents\courses_slides\Cryptography\Final_code _3\cbc_encrypted_cts.jpg"
        
        # Generate a random IV for CBC mode
        iv = os.urandom(8)   # Initialization Vector for CBC mode

        # Load the image and retrieve its binary data
        img = load_image(image_path)
        img_data = img.tobytes()
        mode, size = img.mode, img.size

        # Encrypt the image using DES ECB mode with CTS
        ecb_encrypted = encrypt_ecb_cts(img_data, key)
        save_image(ecb_encrypted, mode, size, ecb_output)

        # Encrypt the image using DES CBC mode with CTS
        cbc_encrypted = encrypt_cbc_cts(img_data, key, iv)
        save_image(cbc_encrypted, mode, size, cbc_output)

        # Print encryption details
        print("Encryption complete. Check output images.")
        print(f"Encryption Key: {key}")
        print(f"CBC IV: {iv.hex()}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()