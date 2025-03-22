# client.py (Alice)
import socket
import pickle
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.serialization import (
    PublicFormat, Encoding, PrivateFormat, NoEncryption, load_pem_public_key
)

def generate_keys():
    """Generate DSA key pair for Alice"""
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
    """Sign a message using Alice's private key"""
    signature = private_key.sign(
        message.encode('utf-8'),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    """Verify Bob's signature using his public key"""
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
    # Generate Alice's DSA key pair
    alice_private_key, alice_public_key, alice_private_bytes, alice_public_bytes = generate_keys()
    print("Alice's DSA key pair generated successfully")
    
    # Connect to Bob's server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 9999)
    
    try:
        client_socket.connect(server_address)
        print(f"Connected to server at {server_address}")
        
        # Exchange public keys with Bob
        bob_public_bytes = client_socket.recv(4096)
        bob_public_key = load_pem_public_key(bob_public_bytes)
        client_socket.send(alice_public_bytes)
        print("Public key exchange completed")
        
        # Create Alice's message
        alice_message = "Hello Bob, this is a secure message from Alice!"
        alice_signature = sign_message(alice_message, alice_private_key)
        
        # Send Alice's message and signature
        message_data = {
            'message': alice_message,
            'signature': alice_signature
        }
        client_socket.send(pickle.dumps(message_data))
        print(f"Sent message to Bob: {alice_message}")
        
        # Receive Bob's response and signature
        data = client_socket.recv(4096)
        received_data = pickle.loads(data)
        bob_message = received_data['message']
        bob_signature = received_data['signature']
        
        print(f"Received response from Bob: {bob_message}")
        
        # Verify Bob's signature
        if verify_signature(bob_message, bob_signature, bob_public_key):
            print("Bob's signature verified successfully!")
        else:
            print("Failed to verify Bob's signature. Potential security breach!")
            
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()