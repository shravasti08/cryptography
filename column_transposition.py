def columnar_transposition_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "")
    key_order = sorted(list(key))
    col_order = {char: i for i, char in enumerate(key)}
    sorted_indices = [col_order[char] for char in key_order]
    num_cols = len(key)
    num_rows = -(-len(plaintext) // num_cols)
    grid = [[''] * num_cols for _ in range(num_rows)]
    index = 0
    for i in range(num_rows):
        for j in range(num_cols):
            if index < len(plaintext):
                grid[i][j] = plaintext[index]
                index += 1
    ciphertext = "".join("".join(grid[row][col] for row in range(num_rows)) for col in sorted_indices)
    return ciphertext

def columnar_transposition_decrypt(ciphertext, key):
    key_order = sorted(list(key))
    col_order = {char: i for i, char in enumerate(key)}
    sorted_indices = [col_order[char] for char in key_order]
    num_cols = len(key)
    num_rows = -(-len(ciphertext) // num_cols)
    grid = [[''] * num_cols for _ in range(num_rows)]
    index = 0
    for col in sorted_indices:
        for row in range(num_rows):
            if index < len(ciphertext):
                grid[row][col] = ciphertext[index]
                index += 1
    plaintext = "".join("".join(row) for row in grid).strip()
    return plaintext

plaintext = "MEET ME AT THE PARK"
key = "ZEBRA"
ciphertext = columnar_transposition_encrypt(plaintext, key)
decrypted_text = columnar_transposition_decrypt(ciphertext, key)
print("Columnar Transposition Cipher:")
print("Ciphertext:", ciphertext)
print("Decryption:", decrypted_text)