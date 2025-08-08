import os
import hashlib
from typing import Tuple, List

def gcd(a: int, b: int) -> int:
    # Compute greatest common divisor
    while b:
        a, b = b, a % b
    return a

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    # Extended GCD returns gcd, x, y such that ax + by = gcd
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    # Modular inverse using extended GCD
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse exists")
    return x % m

def _decompose(n: int) -> Tuple[int, int]:
    # Express n-1 as 2^r * d
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    return r, d

def is_probable_prime(n: int, rounds: int = 12) -> bool:
    # Miller–Rabin primality test
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False
    
    # Decompose n-1 into r and d
    r, d = _decompose(n)
    for _ in range(rounds):
        # Pick random base a
        a = 2 + int.from_bytes(os.urandom(8), "big") % (n - 3)
        x = pow(a, d, n)
        
        # Continue if test passes
        if x == 1 or x == n - 1:
            continue
        
        # Square repeatedly to check
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    # Generate a probable prime of given size
    while True:
        candidate = (1 << (bits - 1)) | int.from_bytes(os.urandom((bits + 7)//8), "big")
        candidate |= 1
        if is_probable_prime(candidate):
            return candidate

def generate_keys(bits: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    # Generate RSA key pair
    p = generate_prime(bits // 2)
    q = generate_prime(bits - p.bit_length())
    while p == q:
        q = generate_prime(bits // 2)
    
    # Compute modulus and totient
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    
    # Ensure e and phi are coprime
    if gcd(e, phi) != 1:
        return generate_keys(bits)
    d = modinv(e, phi)
    return (e, n), (d, n)

def _int_to_bytes(x: int, length: int) -> bytes:
    # Convert integer to bytes
    return x.to_bytes(length, "big")

def _bytes_to_int(b: bytes) -> int:
    # Convert bytes to integer
    return int.from_bytes(b, "big")

def _max_plaintext_len(n: int) -> int:
    # Max block length for plaintext
    return max(1, (n.bit_length() - 1) // 8)

def _modulus_len(n: int) -> int:
    # Byte length of modulus
    return (n.bit_length() + 7) // 8

def encrypt(public_key: Tuple[int, int], plaintext: bytes) -> List[bytes]:
    # Encrypt plaintext into blocks
    e, n = public_key
    block_size = _max_plaintext_len(n)
    k = _modulus_len(n)
    out_blocks = []
    
    # Process each block
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        m = _bytes_to_int(block)
        if m >= n:
            raise ValueError("Block too large")
        c = pow(m, e, n)
        out_blocks.append(_int_to_bytes(c, k))
    return out_blocks

def decrypt(private_key: Tuple[int, int], ciphertext_blocks: List[bytes]) -> bytes:
    # Decrypt ciphertext into plaintext
    d, n = private_key
    k = _modulus_len(n)
    chunks = []
    
    # Process each block
    for cblock in ciphertext_blocks:
        if len(cblock) != k:
            raise ValueError("Block length mismatch")
        c = _bytes_to_int(cblock)
        m = pow(c, d, n)
        mb = m.to_bytes((m.bit_length() + 7) // 8, "big")
        chunks.append(mb)
    return b"".join(chunks)

def sign(private_key: Tuple[int, int], message: bytes) -> bytes:
    # Create digital signature
    d, n = private_key
    k = _modulus_len(n)
    digest = hashlib.sha256(message).digest()
    h_int = _bytes_to_int(digest)
    sig_int = pow(h_int, d, n)
    return _int_to_bytes(sig_int, k)

def verify(public_key: Tuple[int, int], message: bytes, signature: bytes) -> bool:
    # Verify digital signature
    e, n = public_key
    if len(signature) != _modulus_len(n):
        return False
    digest = hashlib.sha256(message).digest()
    h_int = _bytes_to_int(digest)
    s_int = _bytes_to_int(signature)
    check = pow(s_int, e, n)
    return check == h_int
