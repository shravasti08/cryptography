from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import socket

def generate_rsa_keys():
    # Generate RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def start_server(host='localhost', port=5005):
    private_key, public_key = generate_rsa_keys()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print('Server is listening on host - ', host,' port - ',port)
    
    client_socket, address = server_socket.accept()
    print('Connection from : ',address)
    
    try:
        client_socket.send(public_key) # Send public key to client
        print('Sent public key to client')
        
        encrypted_aes_key = client_socket.recv(512)  # Receive encrypted AES key
        print('Received encrypted AES key')
        
        # Decrypt AES key using private RSA key
        rsa_private_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        print("Decrypted AES key successfully")
        
        # Demo: Receive and decrypt a message using AES
        # Receive nonce and encrypted message
        nonce = client_socket.recv(16)
        encrypted_message = client_socket.recv(1024)
        
        # Create AES cipher and decrypt message
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_message = cipher_aes.decrypt(encrypted_message)
        print(f"Decrypted message: {decrypted_message.decode()}")
        
    finally:
        client_socket.close()
        server_socket.close()
        
if __name__ == "__main__":
    start_server()