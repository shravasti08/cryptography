def caesar_encrypt(plaintext, shift):
    """
    Encrypt a message using the Caesar cipher.

    Args:
        plaintext (str): The message to encrypt.
        shift (int): The shift value (key).

    Returns:
        str: The encrypted message.
    """
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():  # Check if it's a letter
            base = ord('A') if char.isupper() else ord('a')  # Determine case
            ciphertext += chr((ord(char) - base + shift) % 26 + base)  # Apply shift
        else:
            ciphertext += char  # Keep non-letters unchanged
    return ciphertext

def caesar_decrypt(ciphertext, shift):
    """
    Decrypt a Caesar cipher by reversing the shift.

    Args:
        ciphertext (str): The encrypted message.
        shift (int): The shift value (key).

    Returns:
        str: The decrypted message.
    """
    return caesar_encrypt(ciphertext, -shift)

def caesar_brute_force(ciphertext):
    """
    Attempt all possible shifts to decrypt the Caesar cipher.

    Args:
        ciphertext (str): The encrypted message.

    Returns:
        None
    """
    for shift in range(1, 26):
        print(f"Shift {shift}: {caesar_decrypt(ciphertext, shift)}")

from collections import Counter

def frequency_analysis(ciphertext):
    """
    Analyze letter frequency in the ciphertext.

    Args:
        ciphertext (str): The encrypted message.

    Returns:
        None
    """
    freq = Counter([char for char in ciphertext if char.isalpha()])
    for char, count in freq.most_common():
        print(f"{char}: {count}")
