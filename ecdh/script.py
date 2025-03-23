import socket
import json
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class ECDHKeyExchange:
    def __init__(self):
        # Generate the private key (which also contains the public key)
        self.private_key = ec.generate_private_key(
            ec.SECP256R1(),  # Standard NIST curve
            default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.shared_key = None
    
    def get_public_bytes(self):
        # Serialize public key to bytes
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def compute_shared_secret(self, peer_public_key_bytes):
        # Deserialize the peer's public key from bytes
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_bytes,
            backend=default_backend()
        )
        
        # Compute shared secret
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Hash the shared secret to get a 256-bit key
        self.shared_key = hashlib.sha256(shared_secret).digest()
        return self.shared_key

class AESCipher:
    def __init__(self, key):
        self.key = key
        self.block_size = 16  # AES block size in bytes
    
    def encrypt(self, plaintext):
        # Generate a random IV
        iv = os.urandom(16)
        
        # Pad the plaintext
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        # Encrypt the data
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def decrypt(self, ciphertext):
        # Extract IV from ciphertext
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        # Decrypt the data
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        # Unpad the plaintext
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode()

# Server implementation
def run_server():
    # Initialize ECDH
    ecdh = ECDHKeyExchange()
    
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 6000)
    print('Starting up server on {} port {}'.format(*server_address))
    server_socket.bind(server_address)
    
    # Listen for incoming connections
    server_socket.listen(1)
    
    while True:
        print('Waiting for a connection...')
        client_socket, client_address = server_socket.accept()
        try:
            print('Connection from', client_address)
            
            # Send public key to client
            server_public_key = ecdh.get_public_bytes()
            client_socket.send(server_public_key)
            
            # Receive client's public key
            client_public_key = client_socket.recv(4096)
            
            # Compute shared secret
            shared_key = ecdh.compute_shared_secret(client_public_key)
            print(f"Shared key derived: {shared_key.hex()}")
            
            # Initialize AES cipher with the shared key
            aes_cipher = AESCipher(shared_key)
            
            # Receive encrypted message from client
            encrypted_message = client_socket.recv(4096)
            
            # Decrypt message
            decrypted_message = aes_cipher.decrypt(encrypted_message)
            print(f"Received encrypted message from client")
            print(f"Decrypted message: {decrypted_message}")
            
            # Send encrypted response to client
            response = "Hello this is the Server ! Your message was received securely."
            encrypted_response = aes_cipher.encrypt(response)
            client_socket.send(encrypted_response)
            
        finally:
            client_socket.close()

# Client implementation
def run_client():
    # Initialize ECDH
    ecdh = ECDHKeyExchange()
    
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 6000)
    print('Connecting to {} port {}'.format(*server_address))
    client_socket.connect(server_address)
    
    try:
        # Receive server's public key
        server_public_key = client_socket.recv(4096)
        
        # Send public key to server
        client_public_key = ecdh.get_public_bytes()
        client_socket.send(client_public_key)
        
        # Compute shared secret
        shared_key = ecdh.compute_shared_secret(server_public_key)
        print(f"Shared key derived: {shared_key.hex()}")
        
        # Initialize AES cipher with the shared key
        aes_cipher = AESCipher(shared_key)
        
        # Encrypt and send a message to the server
        message = "Hello ! I am the Client ! This message is encrypted."
        encrypted_message = aes_cipher.encrypt(message)
        client_socket.send(encrypted_message)
        
        # Receive and decrypt server's response
        encrypted_response = client_socket.recv(4096)
        decrypted_response = aes_cipher.decrypt(encrypted_response)
        print(f"Received encrypted response from server")
        print(f"Decrypted response: {decrypted_response}")
        
    finally:
        client_socket.close()

# Main entry point
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python script.py [client|server]")
        sys.exit(1)
    
    if sys.argv[1] == "server":
        run_server()
    elif sys.argv[1] == "client":
        run_client()
    else:
        print("Invalid argument. Use 'client' or 'server'")
        sys.exit(1)