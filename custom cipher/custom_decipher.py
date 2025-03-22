import random
import string

def create_substitution_tables(key1: str) -> tuple[dict, dict]:
    """Create encryption and decryption substitution tables from key1"""
    if not set(string.ascii_lowercase) <= set(key1.lower()):
        raise ValueError("key1 must contain all letters of the alphabet")
    
    encrypt_table = str.maketrans(string.ascii_lowercase, key1.lower())
    decrypt_table = str.maketrans(key1.lower(), string.ascii_lowercase)
    return encrypt_table, decrypt_table

def substitute(text: str, table: dict) -> str:
    """Apply substitution cipher using provided translation table"""
    return text.lower().translate(table)

def transpose(text: str, block_size: int, encrypt: bool = True) -> str:
    """Apply transposition using specified block size"""
    result = []
    for i in range(0, len(text), block_size):
        block = text[i:i + block_size]
        # Reverse the block for both encryption and decryption
        result.append(block[::-1])
    return ''.join(result)

def remove_padding(text: str, pad_positions: list[int]) -> str:
    """Remove padding characters from known positions"""
    result = list(text)
    for pos in sorted(pad_positions, reverse=True):
        del result[pos]
    return ''.join(result)

def decrypt(ciphertext: str, key1: str, key2: int, pad_positions: list[int]) -> str:
    """
    Decrypt ciphertext by reversing all three layers:
    1. Remove padding
    2. Reverse transposition
    3. Reverse substitution
    """
    # Create substitution tables
    _, decrypt_table = create_substitution_tables(key1)
    
    # Step 1: Remove padding
    text = remove_padding(ciphertext, pad_positions)
    
    # Step 2: Reverse transposition
    text = transpose(text, key2, encrypt=False)
    
    # Step 3: Reverse substitution
    return substitute(text, decrypt_table)

# Example substitution key (shuffled alphabet)
key1 = "qwertyuiopasdfghjklzxcvbnm"
# Block size for transposition
key2 = 3
# Test message
encrypted = "oizo ull lqxkilqctoz"
pad_positions = [5, 11, 17]
# Decrypt
decrypted = decrypt(encrypted, key1, key2, pad_positions)
print(f"Decrypted: {decrypted}")