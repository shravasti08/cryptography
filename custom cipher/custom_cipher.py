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
        print(f"Block: {block}")
        # Reverse the block for both encryption and decryption
        result.append(block[::-1])
    return ''.join(result)

def add_padding(text: str, interval: int) -> tuple[str, list[int]]:
    """Add random padding characters at fixed intervals"""
    result = list(text)
    pad_positions = []
    
    for i in range(interval, len(result) + len(result)//interval, interval + 1):
        pad_char = random.choice(string.ascii_lowercase)
        result.insert(i, pad_char)
        pad_positions.append(i)
    
    return ''.join(result), pad_positions

def remove_padding(text: str, pad_positions: list[int]) -> str:
    """Remove padding characters from known positions"""
    result = list(text)
    for pos in sorted(pad_positions, reverse=True):
        del result[pos]
    return ''.join(result)

def encrypt(plaintext: str, key1: str, key2: int, pad_interval: int = 5) -> tuple[str, list[int]]:
    """
    Encrypt plaintext using all three layers:
    1. Substitution using key1
    2. Transposition using key2 as block size
    3. Random padding at specified intervals
    
    Returns tuple of (ciphertext, padding_positions)
    """
    # Create substitution tables
    encrypt_table, _ = create_substitution_tables(key1)
    
    # Step 1: Substitution
    text = substitute(plaintext, encrypt_table)
    
    # Step 2: Transposition
    text = transpose(text, key2, encrypt=True)
    
    # Step 3: Add padding
    return add_padding(text, pad_interval)

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
message = "this is shravasti"

print(f"Original: {message}")

# Encrypt
encrypted, pad_positions = encrypt(message, key1, key2)
print(f"Encrypted: {encrypted}")
print(f"Padding positions: {pad_positions}")

