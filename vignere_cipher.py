def generate_key(plaintext, key):
    """
    Adjust the key to match the plaintext length.

    Args:
        plaintext (str): The message to encrypt or decrypt.
        key (str): The initial key.

    Returns:
        str: The adjusted key of the same length as the plaintext.
    """
    key = list(key)
    if len(plaintext) == len(key):
        return "".join(key)
    else:
        return "".join(key * (len(plaintext) // len(key)) + key[:len(plaintext) % len(key)])

def vigenere_encrypt(plaintext, key):
    """
    Encrypt using the Vigenère cipher.

    Args:
        plaintext (str): The message to encrypt.
        key (str): The key.

    Returns:
        str: The encrypted message.
    """
    key = generate_key(plaintext, key)
    ciphertext = ""
    for p, k in zip(plaintext, key):
        if p.isalpha():
            base = ord('A') if p.isupper() else ord('a')
            ciphertext += chr((ord(p) - base + ord(k.upper()) - ord('A')) % 26 + base)
        else:
            ciphertext += p
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    """
    Decrypt using the Vigenère cipher.

    Args:
        ciphertext (str): The encrypted message.
        key (str): The key.

    Returns:
        str: The decrypted message.
    """
    key = generate_key(ciphertext, key)
    plaintext = ""
    for c, k in zip(ciphertext, key):
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            plaintext += chr((ord(c) - base - (ord(k.upper()) - ord('A'))) % 26 + base)
        else:
            plaintext += c
    return plaintext
