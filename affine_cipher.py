def mod_inverse(a, m):
    """
    Find modular inverse of a under modulus m.

    Args:
        a (int): The number for which the modular inverse is to be found.
        m (int): The modulus.

    Returns:
        int: The modular inverse of a under m.

    Raises:
        ValueError: If no modular inverse exists.
    """
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse exists.")

def affine_encrypt(plaintext, a, b):
    """
    Encrypt using the Affine cipher.

    Args:
        plaintext (str): The message to encrypt.
        a (int): Multiplicative key.
        b (int): Additive key.

    Returns:
        str: The encrypted message.
    """
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            ciphertext += chr(((a * (ord(char) - base) + b) % 26) + base)
        else:
            ciphertext += char
    return ciphertext

def affine_decrypt(ciphertext, a, b):
    """
    Decrypt using the Affine cipher.

    Args:
        ciphertext (str): The encrypted message.
        a (int): Multiplicative key.
        b (int): Additive key.

    Returns:
        str: The decrypted message.
    """
    a_inv = mod_inverse(a, 26)
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            plaintext += chr(((a_inv * (ord(char) - base - b)) % 26) + base)
        else:
            plaintext += char
    return plaintext

def affine_brute_force(ciphertext):
    """
    Try all possible key pairs to decrypt the Affine cipher.

    Args:
        ciphertext (str): The encrypted message.

    Returns:
        None
    """
    for a in range(1, 26):
        try:
            mod_inverse(a, 26)
            for b in range(26):
                print(f"a={a}, b={b}: {affine_decrypt(ciphertext, a, b)}")
        except ValueError:
            continue

