# client.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import socket

def start_client(host='localhost', port=5005):
    # Create a socket client
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")
    
    try:
        # Receive public key from server
        public_key = client_socket.recv(2048)
        print("Received public key from server")
        
        # Generate AES key
        aes_key = get_random_bytes(32)  # 256-bit key
        print("Generated AES key")
        
        # Encrypt AES key with RSA public key
        rsa_public_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Send encrypted AES key to server
        client_socket.send(encrypted_aes_key)
        print("Sent encrypted AES key to server")
        
         # Demo: Encrypt and send a message using AES
        message = b"Hey there! This is Shravasti :)"
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        nonce = cipher_aes.nonce
        encrypted_message = cipher_aes.encrypt(message)
        
        # Send nonce and encrypted message
        client_socket.send(nonce)
        client_socket.send(encrypted_message)
        print(f"Sent encrypted message: {message.decode()}")
        
    finally:
        client_socket.close()
        
if __name__ == "__main__":
    start_client()