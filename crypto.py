import os
import base64
import random
import json
import sys

# Try to import sympy.randprime; provide a minimal fallback if unavailable
USING_FALLBACK_PRIME = False
try:
    from sympy import randprime  # type: ignore
except Exception:
    USING_FALLBACK_PRIME = True
    def is_probable_prime(n: int, k: int = 10) -> bool:
        if n < 2:
            return False
        # small primes
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
        for p in small_primes:
            if n % p == 0:
                return n == p
        # Miller-Rabin
        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(k):
            a = random.randrange(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def randprime(a: int, b: int) -> int:  # fallback: not cryptographically strong
        while True:
            n = random.randrange(a, b)
            # make odd
            n |= 1
            if is_probable_prime(n):
                return n

# -----------------------------
# 1. BAD: Caesar Cipher
# -----------------------------
def caesar_encrypt(password: str, shift: int = 3) -> str:
    result = ""
    for ch in password:
        result += chr((ord(ch) + shift) % 1114111)  # uses full Unicode
    return result

def caesar_decrypt(cipher: str, shift: int = 3) -> str:
    result = ""
    for ch in cipher:
        result += chr((ord(ch) - shift) % 1114111)
    return result


# -----------------------------
# 2. OK: Vigenère Cipher
# -----------------------------
def vigenere_encrypt(password: str, key: str = "MATH"):
    result = ""
    for i, ch in enumerate(password):
        result += chr((ord(ch) + ord(key[i % len(key)])) % 1114111)
    return result

def vigenere_decrypt(cipher: str, key: str = "MATH"):
    result = ""
    for i, ch in enumerate(cipher):
        result += chr((ord(ch) - ord(key[i % len(key)])) % 1114111)
    return result


# -----------------------------
# 3. Mini-RSA (demo only; fast, insecure)
# -----------------------------
def generate_rsa_keys():
    # Use very small demo primes for speed (INSECURE, for demo only)
    if USING_FALLBACK_PRIME:
        print("[WARNING] Using fallback prime generator. RSA is insecure and for demo only.", file=sys.stderr)
        # Use fallback randprime for small random primes (e.g., 12-14 bits)
        p = randprime(2**12, 2**13)
        q = randprime(2**12, 2**13)
        while q == p:
            q = randprime(2**12, 2**13)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 17  # small e for demo
        # Ensure e and phi are coprime; if not, pick another q
        while phi % e == 0:
            q = randprime(2**12, 2**13)
            while q == p:
                q = randprime(2**12, 2**13)
            n = p * q
            phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        return (e, n), (d, n)
    else:
        p = randprime(2**15, 2**16)
        q = randprime(2**15, 2**16)
        while q == p:
            q = randprime(2**15, 2**16)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        # Ensure e and phi are coprime; if not, pick another prime q
        while phi % e == 0:
            q = randprime(2**15, 2**16)
            while q == p:
                q = randprime(2**15, 2**16)
            n = p * q
            phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        return (e, n), (d, n)


def rsa_encrypt(password: str, pubkey):
    e, n = pubkey
    data = password.encode()
    # Choose chunk size so int(block) < n always
    k = max(1, (n.bit_length() - 1) // 8)
    chunks = []
    for i in range(0, len(data), k):
        block = data[i:i + k]
        m = int.from_bytes(block, "big") if block else 0
        c = pow(m, e, n)
        chunks.append(str(c))
    return ".".join(chunks)


def rsa_decrypt(cipher: str, privkey):
    d, n = privkey
    parts = cipher.split(".") if cipher else []
    out = bytearray()
    for part in parts:
        if not part:
            continue
        c = int(part)
        m = pow(c, d, n)
        blen = (m.bit_length() + 7) // 8
        block = m.to_bytes(blen, "big") if blen > 0 else b""
        out.extend(block)
    return out.decode()


# -----------------------------
# Wrapper that chooses method
# -----------------------------
def encrypt_password(password: str, method: str = "rsa", rsa_keys=None) -> str:
    if method == "caesar":
        return base64.b64encode(caesar_encrypt(password).encode()).decode()
    elif method == "vigenere":
        return base64.b64encode(vigenere_encrypt(password).encode()).decode()
    elif method == "rsa":
        if rsa_keys is None:
            raise ValueError("RSA keys are required for RSA encryption")
        pub, _ = rsa_keys
        return rsa_encrypt(password, pub)
    else:
        raise ValueError("Unknown method")


def decrypt_password(token: str, method: str = "rsa", rsa_keys=None) -> str:
    if method == "caesar":
        return caesar_decrypt(base64.b64decode(token).decode())
    elif method == "vigenere":
        return vigenere_decrypt(base64.b64decode(token).decode())
    elif method == "rsa":
        if rsa_keys is None:
            raise ValueError("RSA keys are required for RSA decryption")
        _, priv = rsa_keys
        return rsa_decrypt(token, priv)
    else:
        raise ValueError("Unknown method")


def save_rsa_keys(username, pub, priv):
    key_file = f"{username}_rsa.key"
    with open(key_file, "w") as f:
        json.dump({'pub': pub, 'priv': priv}, f)


def load_rsa_keys(username):
    key_file = f"{username}_rsa.key"
    if not os.path.exists(key_file):
        return None
    with open(key_file, "r") as f:
        keys = json.load(f)
        pub = tuple(keys['pub'])
        priv = tuple(keys['priv'])
        return pub, priv
