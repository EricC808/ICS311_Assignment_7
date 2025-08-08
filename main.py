from rsa import generate_keys, encrypt, decrypt, sign, verify

def demo():
    # Generate RSA key pair
    public_key, private_key = generate_keys(bits=512)
    print("Public key bits:", public_key[1].bit_length())

    # Define message
    message = b"Hello ICS 311! RSA demo time."
    print("Original:", message)

    # Encrypt the message
    ciphertext_blocks = encrypt(public_key, message)
    print("Encrypted into", len(ciphertext_blocks), "blocks")

    # Decrypt the ciphertext
    recovered = decrypt(private_key, ciphertext_blocks)
    print("Decrypted:", recovered)
    print("Match?", recovered == message)

    # Sign the message
    signature = sign(private_key, message)
    print("Signature valid?", verify(public_key, message, signature))

def main():
    # Run the demo
    demo()

if __name__ == "__main__":
    main()
