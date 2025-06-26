import math
from sympy import isprime

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    for d in range(1, phi):
        if (e * d) % phi == 1:
            return d
    return None

def generate_rsa_keys():
    # Input prime numbers
    while True:
        try:
            p = int(input("Enter the first prime number (p): "))
            if not isprime(p):
                print("The number is not prime. Try again.")
                continue
            q = int(input("Enter the second prime number (q): "))
            if not isprime(q):
                print("The number is not prime. Try again.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter integers.")

    # Calculate RSA parameters
    n = p * q
    phi = (p - 1) * (q - 1)
    print(f"N (modulus): {n}")
    print(f"ϕ(N) (Euler's Totient Function): {phi}")

    # Input public key (e)
    while True:
        try:
            e = int(input("Enter the public key (e): "))
            if gcd(e, phi) == 1 and 1 < e < phi:
                break
            else:
                print("Invalid e. It must be relatively prime to ϕ(N) and 1 < e < ϕ(N).")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    # Calculate private key (d)
    d = mod_inverse(e, phi)
    if d is None:
        print("Failed to compute the modular inverse.")
        return None

    print(f"Public Key: (e={e}, N={n})")
    print(f"Private Key: (d={d}, N={n})")

    return (e, n), (d, n)

def encrypt_message(public_key):
    e, n = public_key
    plaintext = input("Enter the message to encrypt: ")
    ciphertext = [pow(ord(char), e, n) for char in plaintext]

    with open(r"C:\Users\User\Documents\courses_slides\Cryptography\Final_code _3\encrypted_message.txt", "w") as file:
        file.write(" ".join(map(str, ciphertext)))

    print("Encrypted message saved to 'encrypted_message.txt'.")

def decrypt_message(private_key):
    d, n = private_key
    try:
        with open(r"C:\Users\User\Documents\courses_slides\Cryptography\Final_code _3\encrypted_message.txt", "r") as file:
            ciphertext = list(map(int, file.read().split()))
    except FileNotFoundError:
        print("Encrypted message file not found.")
        return

    plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    print(f"Decrypted Message: {plaintext}")

def main():
    print("RSA Key Generation")
    public_key, private_key = generate_rsa_keys()
    if not public_key or not private_key:
        return

    user = input("do you want to encrypt (1) message or decrypt (2) ? (enter 1 or 2)  ").strip().lower()
    if user == "1":
        encrypt_message(public_key)
    elif user == "2":
        decrypt_message(private_key)
    else:
        print("Invalid mode. Please choose '1' or '2'.")

if __name__ == "__main__":
    main()
