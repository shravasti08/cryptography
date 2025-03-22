# server.py (Bob)
import socket
import pickle
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.serialization import (
    PublicFormat, Encoding, PrivateFormat, NoEncryption, load_pem_public_key
)

def generate_keys():
    """Generate DSA key pair for Bob"""
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()
    
    # Serialize keys for storage/transmission
    private_bytes = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, public_key, private_bytes, public_bytes

def sign_message(message, private_key):
    """Sign a message using Bob's private key"""
    signature = private_key.sign(
        message.encode('utf-8'),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    """Verify Alice's signature using her public key"""
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def main():
    # Generate Bob's DSA key pair
    bob_private_key, bob_public_key, bob_private_bytes, bob_public_bytes = generate_keys()
    print("Bob's DSA key pair generated successfully")
    
    # Set up server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 9999)
    server_socket.bind(server_address)
    server_socket.listen(1)
    print(f"Server is listening on {server_address}")
    
    try:
        while True:
            print("Waiting for a connection...")
            client_socket, client_address = server_socket.accept()
            print(f"Connection from {client_address}")
            
            try:
                # Exchange public keys with Alice
                client_socket.send(bob_public_bytes)
                alice_public_bytes = client_socket.recv(4096)
                alice_public_key = load_pem_public_key(alice_public_bytes)
                print("Public key exchange completed")
                
                # Receive Alice's message and signature
                data = client_socket.recv(4096)
                if not data:
                    break
                
                received_data = pickle.loads(data)
                alice_message = received_data['message']
                alice_signature = received_data['signature']
                
                print(f"Received message from Alice: {alice_message}")
                
                # Verify Alice's signature
                if verify_signature(alice_message, alice_signature, alice_public_key):
                    print("Alice's signature verified successfully!")
                    
                    # Create Bob's response
                    bob_message = f"Hello Alice, I received your message: '{alice_message}'"
                    bob_signature = sign_message(bob_message, bob_private_key)
                    
                    # Send Bob's response and signature
                    response_data = {
                        'message': bob_message,
                        'signature': bob_signature
                    }
                    client_socket.send(pickle.dumps(response_data))
                    print(f"Sent response to Alice: {bob_message}")
                else:
                    print("Failed to verify Alice's signature. Potential security breach!")
                    
            finally:
                client_socket.close()
                
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()